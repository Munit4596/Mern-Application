
# Use the official Node.js 18 image
FROM node:18

# Set the working directory in the container
WORKDIR /app

# Copy the package*.json files to the working directory
COPY package*.json ./

# Install the dependencies with verbose logging
RUN npm install --verbose

# Copy the application code to the working directory
COPY . .

# Expose the port that the application will run on
EXPOSE 3000

# Run the command to start the development server
CMD ["npm", "start"]