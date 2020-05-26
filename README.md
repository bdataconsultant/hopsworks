# Introduction

Giotto big data plaform repository.

# Getting Started

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
Under giotto-platform-v1.0.0/ run:

```sh
mvn clean package -DtargetCustomer=CLIENT_NAME
```
CUSTOMER_NAME value is the name of the customer folder in app/customer_assets. When targetCustomer option isn't specified, "DEFAULT" customer name is used.

# Contribute

TODO: Explain how other users and developers can contribute to make your code better.

If you want to learn more about creating good readme files then refer the following [guidelines](https://www.visualstudio.com/en-us/docs/git/create-a-readme). You can also seek inspiration from the below readme files:

- [ASP.NET Core](https://github.com/aspnet/Home)
- [Visual Studio Code](https://github.com/Microsoft/vscode)
- [Chakra Core](https://github.com/Microsoft/ChakraCore)
