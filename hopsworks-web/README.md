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
	npm install -g bower
    npm install -g grunt-cli
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
