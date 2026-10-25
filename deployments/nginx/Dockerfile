FROM nginx:alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /usr/share/nginx/html/index.html
RUN mkdir -p /var/cache/nginx /var/log/nginx && chown -R 101:101 /var/cache/nginx /var/log/nginx /usr/share/nginx/html
USER 101:101
EXPOSE 8080
