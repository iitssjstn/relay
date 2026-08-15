FROM nginx:alpine

# Relay is a single static HTML/JS/CSS app — no build step, no backend.
# nginx just serves the file; all AI-provider calls happen client-side
# straight from the user's browser.
COPY src/ /usr/share/nginx/html/

EXPOSE 80
