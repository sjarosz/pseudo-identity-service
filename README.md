# Identity Data Service Simulator

## Project Overview
This project provides a Flask-based API that serves identity data from a JSON file. The application can be deployed either as a standalone Docker service or as a Kubernetes-managed service.  Ideal for testing passthrough authentication and OpenICF connector operations for provisioning and reconciliation.

The sample data in data.json, can be modified and the schema can as well.  The sample is just a getting started schema and data.  The only requirement for the schema, is that the users are in the collection of 'users' and that each user has an 'id' attribute.

## File Descriptions

- **app.py**: Flask application that serves various endpoints for retrieving and managing data.
- **data.json**: JSON file containing user data utilized by the Flask application.
- **requirements.txt**: Specifies the dependencies required for the Flask application.
- **Dockerfile**: Defines the Docker image, including dependencies and the Flask runtime environment.
- **deploy.sh**: Kubernetes deployment script that deletes any existing deployment and applies a new one.
- **k8s.yaml**: Kubernetes deployment and service definition for running the Flask application.
- **template.yaml**: Template Kubernetes configuration file that is used for generating `k8s.yaml` dynamically.
- **process-template.sh**: Script that processes `template.yaml`, injecting base64-encoded application files into the Kubernetes ConfigMap before generating `k8s.yaml`.
- **Pseudo Data Service Collection.postman_collection.json**: Postman collection that exercises the data service

## Features

1. **CRUD operation support**: The API supports Create, Read, Update, and Delete (CRUD) operations for the identity store.
2. **Password Reset Support**: The update operation allows users to reset their passwords.
3. **OAuth2 Authentication Credentials**: OAuth2 endpoint authentication credentials function with password reset. Starting Password is 'P@ssw0rd', password can be changed in an update and then future calls to get token, must supply updated password.
4. **Explicitly Trusted Token**:  OAuth2 tokens are explicitly trusted. Simulator just expects presents of a token in the header.  Postman collection handels setting and recalling required token values.
5. **Supported API Operations**:
   - Add user
   - Delete user
   - Update user
   - Count users
   - Find user
   - Show all users
   - Issue OAuth2 token (ROPC flow)



## Deployment Options

### Running Locally with Docker
To run the Flask application locally using Docker:

1. **Build the Docker Image:**
   ```sh
   docker build -t flask-app .
   ```

2. **Run the Container:**
   ```sh
   docker run -p 5000:5000 flask-app
   ```
   This will expose the application on `http://localhost:5000`.

### Deploying on Kubernetes

1. **Generate Kubernetes Manifest:**
   Run the following script to generate `k8s.yaml` dynamically from `template.yaml`:
   ```sh
   ./process-template.sh
   ```

2. **Deploy the Application:**
   Apply the generated `k8s.yaml` file:
   ```sh
   kubectl apply -f k8s.yaml
   ```

3. **Verify Deployment:**
   Check the running pods:
   ```sh
   kubectl get pods
   ```
   
4. **Access the Application:**
   If running within a Kubernetes cluster, you may need to set up port forwarding:
   ```sh
   kubectl port-forward svc/flask-app-service 8080:80
   ```
   The application will then be accessible at `http://localhost:8080`.

## Notes
- Ensure that Kubernetes is properly configured before deploying.
- The `process-template.sh` script dynamically injects the latest `app.py` and `data.json` into the ConfigMap to ensure the most updated version is deployed.
- Logs are written to `/app/logs/app.log` inside the container.
- Modify `k8s.yaml` to adjust scaling, resource limits, or other configurations as needed.
