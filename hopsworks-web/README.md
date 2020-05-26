# Introduction

This is the Giotto big data plaform front-end application. It's an Angularjs application using npm and bower as package manager and grunt as development task runner.

# Getting Started

### 1. Pull project from the repository
	git clone https://almatoolbox.visualstudio.com/Giotto/_git/giotto-platform-v.1.0.0
    cd ./hopsworks-web/yo
	
### 2. Install packages
```sh
	npm install -g bower@1.8.8
    npm install -g grunt-cli@1.2.0
	npm install
    bower install
	
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
