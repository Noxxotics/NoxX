# Use Node.js 20 LTS
FROM node:20-alpine

# Create app directory
WORKDIR /app

# Copy package files first (better Docker caching)
COPY package*.json ./

# Install production dependencies
RUN npm install

# Copy the rest of the project
COPY . .

# Railway sets PORT automatically
ENV NODE_ENV=production

# Expose the application port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
