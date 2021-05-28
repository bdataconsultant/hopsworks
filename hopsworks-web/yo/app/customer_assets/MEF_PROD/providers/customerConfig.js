(function(angular) {
    "use strict";
    angular.module("hopsWorksApp").provider("customerConfig", function() {
      var values = {
        showPonFooter: false,
        dataCatalogSidemenuUrl: "http://datacatalog.dt.tesoro.it/",
        nifiSidemenuUrl: "http://dataingestion.dt.tesoro.it/"
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
  