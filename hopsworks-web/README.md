# Introduction

This is the Giotto big data plaform front-end application. It's an Angularjs application using npm and bower as package manager and grunt as development task runner.

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

CUSTOMER_NAME value is the name of the customer folder in app/customer_assets. When targetCustomer option isn't specified, "DEFAULT" client name is used.

# Contribute

TODO: Explain how other users and developers can contribute to make your code better.

If you want to learn more about creating good readme files then refer the following [guidelines](https://www.visualstudio.com/en-us/docs/git/create-a-readme). You can also seek inspiration from the below readme files:

- [ASP.NET Core](https://github.com/aspnet/Home)
- [Visual Studio Code](https://github.com/Microsoft/vscode)
- [Chakra Core](https://github.com/Microsoft/ChakraCore)
## Front-end Development
The javascript produced by building maven is obsfuscated. For debugging javascript, we recommend that you use the following script
to deploy changes to HTML or javascript to your vagrant machine:

```sh
cd scripts
./js.sh
```

You should also add the chef recipe to the end of your Vagrantfile (or Karamel cluster definition):
```
 hopsworks::dev
```

To allow Cross-Origin Resource Sharing for development uncomment the AllowCORSFilter registration line in 
io.hops.hopsworks.rest.application.config.ApplicationConfig then build and redeploy hopsworks-ear
 ```
 package io.hops.hopsworks.rest.application.config;
 ...
 public class ApplicationConfig extends ResourceConfig {
   ...
   public ApplicationConfig() {
    ...
    //uncomment to allow Cross-Origin Resource Sharing
    //register(io.hops.hopsworks.api.filter.AllowCORSFilter.class);
    ...
 ```
#### Build Requirements (for Ubuntu)
- Node version 11 (maximum)
- Node version 6

```sh
sudo npm cache clean
# You must have a version of bower > 1.54
sudo npm install bower -g
sudo npm install grunt -g
```

#### For development

You can build Hopsworks without running grunt/bower using:

```
mvn install -P-dist
```

Then run your script to upload your javascript to snurran.sics.se:

```
cd scripts
./deploy.sh [yourName]
```
