(function (angular) {
  "use strict";
  angular.module("hopsWorksApp").provider("customerConfig", function () {
    var values = {
      showPonFooter: true,
      header: {
        logoDir: "images/big-data-logo-header.png",
        appContext: "bigdata",
        appTitle: "SMART CITY PLATFORM",
        oauth2LogOutUrl: "https://smartcityplatform.develop.it/oidc/logout",
        logOutRedirectUrl: "https://smartcityplatform.develop.it/oneadmin/login",
        federatedLogoutUrl: null,
        appUrlsConfig: {
          bigdata: "/giotto-web",
          iot: "/home",
          admin: "/oneadmin",
          udm: "/udm-fe"
        }
      },
      main: "#337ab7",
      gradientSecondary: "#2E353D",
      border: "#337ab7",
      hover: "#337ab7",
      headerTitleColor: "#337ab7",
      headerPrimary: "#e0e0e0",
      headerSecondary: "#337ab7",
      headerLogoHeight: "55px",
      footerImgWidth: "340px",
      logo: "images/big-data-logo-header.png",
      loginLogo: "images/big-data-logo-login.png",
      favIcon: "images/giotto-favi.png",
      platformHeaderLogo: "images/big-data-logo.png",
      footerImage: "images/pon-metro-logo.png"
    };

    return {
      $get: function () {
        return values;
      },
      set: function (constants) {
        angular.extend(values, constants);
      }
    };
  });
})(angular);
