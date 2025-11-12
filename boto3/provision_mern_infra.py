#!/usr/bin/env python3
import json
import time
import zipfile
import io
import base64
import boto3
from botocore.exceptions import ClientError

# ===================== CONFIG =====================
REGION = "ca-central-1"
PROJECT = "mern-iac"

# VPC & subnets
CIDR_VPC = "10.0.0.0/16"
SUBNETS = [
    ("10.0.1.0/24", "ca-central-1a"),
    ("10.0.2.0/24", "ca-central-1b"),
]

# Security: for demo open 80/3000/3001 to world, 22 to YOUR IP
YOUR_IP_CIDR = "0.0.0.0/0"   # TODO: set your IP like "x.x.x.x/32" for SSH

# EC2/ASG settings
INSTANCE_TYPE = "t3.micro"
AMI_ID = "ami-0abac8735a38475db"      # <= TODO step below
KEY_NAME = "mernapplication"        # <= TODO step below

# ECR repos (images you push from Jenkins)
BACKEND_SERVICES = ["hello-service", "profile-service"]  # will run latest tags

# Optional Lambda
CREATE_LAMBDA = True
# ==================================================

session = boto3.Session(region_name=REGION)
ec2 = session.client("ec2")
ec2_res = session.resource("ec2")
iam = session.client("iam")
sts = session.client("sts")
autoscaling = session.client("autoscaling")
lt = session.client("ec2")
logs = session.client("logs")
lambda_client = session.client("lambda")
ecr = session.client("ecr")

def ensure_vpc():
    name = f"{PROJECT}-vpc"
    vpcs = ec2.describe_vpcs(Filters=[{"Name":"tag:Name","Values":[name]}]).get("Vpcs", [])
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        print(f"[VPC] Using existing {vpc_id}")
        return vpc_id
    resp = ec2.create_vpc(CidrBlock=CIDR_VPC, TagSpecifications=[{
        "ResourceType":"vpc","Tags":[{"Key":"Name","Value":name},{"Key":"Project","Value":PROJECT}]
    }])
    vpc_id = resp["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    print(f"[VPC] Created {vpc_id}")
    return vpc_id

def ensure_igw_and_route(vpc_id):
    igws = ec2.describe_internet_gateways(Filters=[{"Name":"attachment.vpc-id","Values":[vpc_id]}]).get("InternetGateways",[])
    if igws:
        igw_id = igws[0]["InternetGatewayId"]
    else:
        igw = ec2.create_internet_gateway(TagSpecifications=[{
            "ResourceType":"internet-gateway","Tags":[{"Key":"Name","Value":f"{PROJECT}-igw"}]
        }])
        igw_id = igw["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    print(f"[IGW] {igw_id}")

    rts = ec2.describe_route_tables(
        Filters=[{"Name":"vpc-id","Values":[vpc_id]},{"Name":"tag:Name","Values":[f"{PROJECT}-public-rt"]}]
    )["RouteTables"]
    if rts:
        rt_id = rts[0]["RouteTableId"]
    else:
        rt = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=[{
            "ResourceType":"route-table","Tags":[{"Key":"Name","Value":f"{PROJECT}-public-rt"}]
        }])
        rt_id = rt["RouteTable"]["RouteTableId"]
    routes = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]["Routes"]
    if not any(r.get("DestinationCidrBlock")=="0.0.0.0/0" for r in routes):
        try:
            ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
        except ClientError as e:
            if "RouteAlreadyExists" not in str(e):
                raise
    return rt_id

def ensure_public_subnets(vpc_id, rt_id):
    subnet_ids = []
    for cidr, az in SUBNETS:
        name = f"{PROJECT}-public-{az[-1]}"
        existing = ec2.describe_subnets(
            Filters=[{"Name":"vpc-id","Values":[vpc_id]},{"Name":"cidr-block","Values":[cidr]}]
        )["Subnets"]
        if existing:
            sid = existing[0]["SubnetId"]
        else:
            resp = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=az,
                TagSpecifications=[{"ResourceType":"subnet","Tags":[{"Key":"Name","Value":name},{"Key":"Project","Value":PROJECT}]}]
            )
            sid = resp["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value":True})
        assoc = ec2.describe_route_tables(Filters=[{"Name":"association.subnet-id","Values":[sid]}])["RouteTables"]
        if not assoc:
            ec2.associate_route_table(SubnetId=sid, RouteTableId=rt_id)
        subnet_ids.append(sid)
        print(f"[Subnet] {sid} ({az})")
    return subnet_ids

def ensure_sg(vpc_id):
    name = f"{PROJECT}-backend-sg"
    sgs = ec2.describe_security_groups(
        Filters=[{"Name":"group-name","Values":[name]},{"Name":"vpc-id","Values":[vpc_id]}]
    ).get("SecurityGroups",[])
    if sgs:
        sg_id = sgs[0]["GroupId"]
    else:
        sg = ec2.create_security_group(
            GroupName=name, Description="Backend SG for MERN",
            VpcId=vpc_id, TagSpecifications=[{"ResourceType":"security-group","Tags":[{"Key":"Name","Value":name}]}]
        )
        sg_id = sg["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":YOUR_IP_CIDR, "Description":"SSH"}]},
                {"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"HTTP"}]},
                {"IpProtocol":"tcp","FromPort":3000,"ToPort":3000,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"helloService"}]},
                {"IpProtocol":"tcp","FromPort":3001,"ToPort":3001,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"profileService"}]},
            ]
        )
    print(f"[SG] {sg_id}")
    return sg_id

def ensure_instance_role():
    role_name = f"{PROJECT}-ec2-role"
    profile_name = f"{PROJECT}-ec2-profile"
    assume = {
        "Version":"2012-10-17",
        "Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]
    }
    try:
        iam.get_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume), Description="EC2 role for pulling from ECR and CW logs")
    # policies
    for arn in ["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
                "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"]:
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        except ClientError:
            pass
    try:
        iam.get_instance_profile(InstanceProfileName=profile_name)
    except iam.exceptions.NoSuchEntityException:
        iam.create_instance_profile(InstanceProfileName=profile_name)
    try:
        iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except ClientError as e:
        if "EntityAlreadyExists" not in str(e):
            raise
    print(f"[IAM] role={role_name} profile={profile_name}")
    return role_name, profile_name

def user_data_script(account_id):
    repos_pull = "".join([f"docker pull {account_id}.dkr.ecr.{REGION}.amazonaws.com/{svc}:latest || true\n" for svc in BACKEND_SERVICES])
    return f"""#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
apt-get update -y && apt-get install -y docker-ce docker-ce-cli containerd.io
systemctl enable --now docker

aws ecr get-login-password --region {REGION} | docker login --username AWS --password-stdin {account_id}.dkr.ecr.{REGION}.amazonaws.com
{repos_pull}
docker run -d --restart=always -p 3000:3000 {account_id}.dkr.ecr.{REGION}.amazonaws.com/hello-service:latest || true
docker run -d --restart=always -p 3001:3001 {account_id}.dkr.ecr.{REGION}.amazonaws.com/profile-service:latest || true
"""

def ensure_launch_template(sg_id, subnet_ids, profile_name):
    name = f"{PROJECT}-lt"
    account_id = sts.get_caller_identity()["Account"]
    ud = user_data_script(account_id)
    user_data_b64 = base64.b64encode(ud.encode("utf-8")).decode("utf-8")
    try:
        resp = lt.create_launch_template(
            LaunchTemplateName=name,
            LaunchTemplateData={
                "ImageId": AMI_ID,
                "InstanceType": INSTANCE_TYPE,
                "KeyName": KEY_NAME,
                "IamInstanceProfile": {"Name": profile_name},
                "SecurityGroupIds": [sg_id],
                "UserData": user_data_b64,
                "TagSpecifications":[{"ResourceType":"instance","Tags":[{"Key":"Name","Value":f"{PROJECT}-backend"}]}]
            },
            TagSpecifications=[{"ResourceType":"launch-template","Tags":[{"Key":"Name","Value":name}]}]
        )
        lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
        ver = resp["LaunchTemplate"]["LatestVersionNumber"]
        print(f"[LT] created id={lt_id} v={ver}")
    except ClientError as e:
        if "InvalidLaunchTemplateName.AlreadyExistsException" in str(e):
            existing = lt.describe_launch_templates(LaunchTemplateNames=[name])["LaunchTemplates"][0]
            lt_id = existing["LaunchTemplateId"]
            respv = lt.create_launch_template_version(
                LaunchTemplateId=lt_id,
                LaunchTemplateData={
                    "ImageId": AMI_ID,
                    "InstanceType": INSTANCE_TYPE,
                    "KeyName": KEY_NAME,
                    "IamInstanceProfile": {"Name": profile_name},
                    "SecurityGroupIds": [sg_id],
                    "UserData": user_data_b64,
                    "TagSpecifications":[{"ResourceType":"instance","Tags":[{"Key":"Name","Value":f"{PROJECT}-backend"}]}]
                }
            )
            ver = respv["LaunchTemplateVersion"]["VersionNumber"]
            lt.modify_launch_template(LaunchTemplateId=lt_id, DefaultVersion=str(ver))
            print(f"[LT] updated {lt_id} -> default version {ver}")
        else:
            raise
    return name

def ensure_asg(lt_name, subnet_ids):
    name = f"{PROJECT}-asg"
    subnets_csv = ",".join(subnet_ids)
    try:
        autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=name,
            LaunchTemplate={"LaunchTemplateName": lt_name},
            MinSize=1, MaxSize=2, DesiredCapacity=1,
            VPCZoneIdentifier=subnets_csv,
            HealthCheckType="EC2",
            HealthCheckGracePeriod=120,
            Tags=[{"Key":"Name","Value":name,"PropagateAtLaunch":True}]
        )
        print(f"[ASG] created {name}")
    except ClientError as e:
        if "AlreadyExists" in str(e):
            autoscaling.update_auto_scaling_group(
                AutoScalingGroupName=name,
                LaunchTemplate={"LaunchTemplateName": lt_name},
                MinSize=1, MaxSize=2, DesiredCapacity=1,
                VPCZoneIdentifier=subnets_csv
            )
            print(f"[ASG] updated {name}")
        else:
            raise

def ensure_lambda_role():
    role_name = f"{PROJECT}-lambda-role"
    assume = {
        "Version":"2012-10-17",
        "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
    }
    try:
        iam.get_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume), Description="Lambda basic execution")
    try:
        iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    except ClientError:
        pass
    return role_name

def ensure_lambda(role_name):
    fn_name = f"{PROJECT}-hello-lambda"
    code = b"""
def handler(event, context):
    return {"statusCode": 200, "body": "Hello from Lambda via Boto3!"}
"""
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("lambda_function.py", code)
    zbytes = zbuf.getvalue()
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    try:
        lambda_client.get_function(FunctionName=fn_name)
        lambda_client.update_function_code(FunctionName=fn_name, ZipFile=zbytes, Publish=True)
        print(f"[Lambda] updated code {fn_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            lambda_client.create_function(
                FunctionName=fn_name,
                Runtime="python3.11",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zbytes},
                Timeout=10,
                MemorySize=128,
                Publish=True,
                Tags={"Project": PROJECT}
            )
            print(f"[Lambda] created {fn_name}")
        else:
            raise

def main():
    print(f"Region: {REGION}")
    account = sts.get_caller_identity()["Account"]
    print(f"Account: {account}")

    vpc_id = ensure_vpc()
    rt_id = ensure_igw_and_route(vpc_id)
    subnet_ids = ensure_public_subnets(vpc_id, rt_id)
    sg_id = ensure_sg(vpc_id)
    role_name, profile_name = ensure_instance_role()

    if AMI_ID.startswith("ami-REPLACE") or KEY_NAME == "REPLACE_ME":
        raise SystemExit("Set AMI_ID and KEY_NAME at the top of the file before running.")

    lt_name = ensure_launch_template(sg_id, subnet_ids, profile_name)
    ensure_asg(lt_name, subnet_ids)

    if CREATE_LAMBDA:
        lr = ensure_lambda_role()
        time.sleep(5)  # small IAM propagation buffer
        ensure_lambda(lr)

    print("\n=== DONE ===")
    print(f"VPC: {vpc_id}")
    print(f"Subnets: {subnet_ids}")
    print(f"SecurityGroup: {sg_id}")
    print(f"LaunchTemplate: {lt_name}")
    print(f"ASG: {PROJECT}-asg")
    if CREATE_LAMBDA:
        print(f"Lambda: {PROJECT}-hello-lambda")

if __name__ == "__main__":
    main()
