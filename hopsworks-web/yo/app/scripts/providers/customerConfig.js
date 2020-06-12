(function(angular) {
  "use strict";
  angular.module("hopsWorksApp").provider("customerConfig", function() {
    var values = {
      showPonFooter: true,
      header: {
        logoDir: "images/big-data-logo-header.png",
        appContext: "bigdata",
        appTitle: "SMART CITY PLATFORM",
        appUrlsConfig: {
          bigdata: "/giotto-web",
          iot: "/home",
          admin: "/oneadmin"
        }
      }
    };

    return {
      $get: function() {
        return values;
      },
      set: function(constants) {
        angular.extend(values, constants);
      }
    };
  });
})(angular);
