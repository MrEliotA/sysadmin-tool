# فرانت سبک با Nginx
FROM nginx:alpine

# حذف کانفیگ پیش‌فرض و افزودن کانفیگ ما
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf

# کپی فایل‌های استاتیک
COPY index.html /usr/share/nginx/html/index.html
COPY style.css /usr/share/nginx/html/style.css
COPY app.js /usr/share/nginx/html/app.js

# سلامت ساده
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost/ || exit 1
