# Use the Nginx image
FROM nginx

# Remove the default nginx.conf
RUN rm /etc/nginx/conf.d/default.conf
RUN apt-get update && apt-get install -y nginx-extras
# Replace with our own nginx.conf
COPY nginx.conf /etc/nginx/conf.d/

COPY cert.pem /etc/ssl/certs/cert.pem
COPY key.pem /etc/ssl/private/key.pem