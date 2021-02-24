'use strict';
/*
 * Service allowing fetching job history objects by type.
 */
angular.module('hopsWorksApp')

    .factory('CustomizationService', ['$http', function ($http) {
        var service = {

            /**
             * @returns {undefined}.
             */
            getCustomization: function () {
                var req = {
                    method: 'GET',
                    url: '/configuration-service/api/theme/customization',
                    headers: {
                        'Content-Type': 'application/json;charset=utf-8',
                    }
                };
                return $http(req);
            }
        };
        return service;
    }]);
