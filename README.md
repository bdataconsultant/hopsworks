# Introduction

Giotto big data plaform repository.

# Getting Started
## Web app
### 1. Pull project from the repository
	git clone https://almatoolbox.visualstudio.com/Giotto/_git/giotto-platform-v.1.0.0
    git checkout develop
    cd ./hopsworks-web/yo

### 2. Install packages
```sh
	npm install -g bower@1.8.8
    npm install -g grunt-cli@1.2.0
	npm install
    bower install
```

If 'npm install' log shows this error:
```
request to http://jfrog.almaviva.it:8081/artifactory/api/npm/giotto-npm/@giotto-jfrog%2fgiotto-platform-header failed, reason: getaddrinfo ENOTFOUND jfrog.almaviva.it
```

Add this line to your /etc/hosts file (C:\Windows\System32\drivers\etc\hosts on windows):
```
10.207.127.8 jfrog.almaviva.it
```

### 3. Start dev server
You can run a local dev server using the serve task defined in Gruntfile.js:

```sh
grunt serve --targetCustomer=CUSTOMER_NAME
```

CUSTOMER_NAME value is the name of the customer folder in app/customer_assets. When targetCustomer option isn't specified, "DEFAULT" customer name is used.

# Build and Test

## Maven build
In giotto-platform-v1.0.0 directory run:

```sh
mvn clean install -DtargetCustomer=CUSTOMER_NAME
```
CUSTOMER_NAME value is the name of the customer folder in app/customer_assets. When targetCustomer option isn't specified, "DEFAULT" customer name is used.

# Customer build configurtion

It is possible to define a build profile vy creating a folder under hopsworks-web/app/customer_assets/CUSTOMER_NAME

this folder may contain:
-- an "images" folder: all the images in this folder will be copied in the app/iamges folder, replacing any already existent images with the same name.
-- a "providers" folder: this folder can contain a customerConfig.js file. Configurations specified in this file will be injected in the MainCtrl.js controller.
-- a "styles" folder: in this folder you can define a custom.css. If you want add more css files you need to add them as <link> to the app/index.html file.

# Contribute

TODO: Explain how other users and developers can contribute to make your code better.

If you want to learn more about creating good readme files then refer the following [guidelines](https://www.visualstudio.com/en-us/docs/git/create-a-readme). You can also seek inspiration from the below readme files:

- [ASP.NET Core](https://github.com/aspnet/Home)
- [Visual Studio Code](https://github.com/Microsoft/vscode)
- [Chakra Core](https://github.com/Microsoft/ChakraCore)
