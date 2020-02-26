# Introduction

Giotto big data plaform repository.

# Getting Started
## Web app
### 1. Pull project from the repository
	git clone https://almatoolbox.visualstudio.com/Giotto/_git/giotto-platform-v.1.0.0
    cd ./hopsworks-web/yo

### 2. Replace jfrog credential in hopsworks-web/yo/.npmrc
```
@giotto-jfrog:registry=http://jfrog.almaviva.it:8081/artifactory/api/npm/giotto-npm/
//jfrog.almaviva.it:8081/artifactory/api/npm/giotto-npm/:_password=
//jfrog.almaviva.it:8081/artifactory/api/npm/giotto-npm/:username=
//jfrog.almaviva.it:8081/artifactory/api/npm/giotto-npm/:email=
//jfrog.almaviva.it:8081/artifactory/api/npm/giotto-npm/:always-auth=true
```

### 3. Install packages
```sh
	npm install -g bower
	npm install
    bower install
    npm install -g grunt-cli
```

### 4. Start dev server
You can run a local dev server using the serve task defined in Gruntfile.js:

```sh
grunt serve --targetCustomer=CUSTOMER_NAME
```

CUSTOMER_NAME value is the name of the customer folder in app/customer_assets. When targetCustomer option isn't specified, "DEFAULT" client name is used.


# Build and Test

## Maven build
Under giotto-platform-v1.0.0/ run:

```sh
mvn clean package -DtargetCustomer=CLIENT_NAME
```
CLIENT_NAME value is the name of the client folder in app/customer_assets. When targetCustomer option isn't specified, "DEFAULT" client name is used.

# Contribute

TODO: Explain how other users and developers can contribute to make your code better.

If you want to learn more about creating good readme files then refer the following [guidelines](https://www.visualstudio.com/en-us/docs/git/create-a-readme). You can also seek inspiration from the below readme files:

- [ASP.NET Core](https://github.com/aspnet/Home)
- [Visual Studio Code](https://github.com/Microsoft/vscode)
- [Chakra Core](https://github.com/Microsoft/ChakraCore)
