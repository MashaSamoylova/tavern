FROM python:3.6-stretch

RUN pip3.6 install numpy

RUN apt-get update
RUN apt-get -y install curl gnupg
RUN curl -sL https://deb.nodesource.com/setup_11.x  | bash -
RUN apt-get install -y nodejs

# Create app directory
WORKDIR /root/app

COPY package.json .
RUN npm install --loglevel=error

COPY . .

EXPOSE 8080
ENTRYPOINT ["npm", "start"]