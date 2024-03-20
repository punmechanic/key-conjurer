FROM node:20.0 as build
RUN mkdir /sources
COPY frontend/ /sources/
RUN cd sources/ && npm install
RUN cd sources/ && npm run-script build

FROM nginx
COPY --from=build /sources/dist/ /usr/share/nginx/html/
