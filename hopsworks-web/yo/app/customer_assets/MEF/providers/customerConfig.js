(function(angular) {
    "use strict";
    angular.module("hopsWorksApp").provider("customerConfig", function() {
      var values = {
        showPonFooter: false,
        dataCatalogSidemenuUrl: "http://datacatalog-coll.dt.tesoro.it:21000",
        nifiSidemenuUrl: "https://10.46.112.83:9443/nifi/login"
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
  