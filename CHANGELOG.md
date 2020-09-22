## [2.0.0](https://github.com/mrichardson03/panos-ips-reports/compare/v1.0.0...v2.0.0) (2020-09-22)


### ⚠ BREAKING CHANGES

* this changes the cli commands to run the scripts

### Features

* add device group parsing ([da9ba7d](https://github.com/mrichardson03/panos-ips-reports/commit/da9ba7d19a7b8e40e4638fa5f7b0c8587157efab))
* add future statements ([c93028e](https://github.com/mrichardson03/panos-ips-reports/commit/c93028ed6205711fea3370473064eca3a2dae1ef))
* add panorama class and tests ([3d2d6b9](https://github.com/mrichardson03/panos-ips-reports/commit/3d2d6b902db4ef9e17553e2027d5d3222b957a58))
* do xml parsing in create_from_element() ([21b1d69](https://github.com/mrichardson03/panos-ips-reports/commit/21b1d6976f096f439a1a330de9c87ce1e41f65a3))
* move reports into panos_util package ([a0bd77b](https://github.com/mrichardson03/panos-ips-reports/commit/a0bd77b25119acd3fa157ab6594043a89d77bd33))
* remove standalone scripts ([288c7b4](https://github.com/mrichardson03/panos-ips-reports/commit/288c7b42a1a205f6b5ee195c19ad3cb9b12a8e5c))
* remove xmltodict dependency ([f4d50d9](https://github.com/mrichardson03/panos-ips-reports/commit/f4d50d9b56267fe658bb1ac4c67a9e246c367bdc))
* Support nested device groups. ([950d190](https://github.com/mrichardson03/panos-ips-reports/commit/950d190001844a807988199b21571ae798f353ac)), closes [#3](https://github.com/mrichardson03/panos-ips-reports/issues/3)


### Bug Fixes

* Add debug statement for bad profile group ([e36b1d5](https://github.com/mrichardson03/panos-ips-reports/commit/e36b1d56fee7c207aad8b8e8ad756c594473d888))
* change pypi classifier ([a1adf07](https://github.com/mrichardson03/panos-ips-reports/commit/a1adf07bd240f1fd55a1a27fdcbd7128e74ed45f))
* Handle IOError when reading input file ([609d7a3](https://github.com/mrichardson03/panos-ips-reports/commit/609d7a3af142c3c462acee241a44354c92bdc7b7)), closes [#4](https://github.com/mrichardson03/panos-ips-reports/issues/4)
* remove unused code ([55643de](https://github.com/mrichardson03/panos-ips-reports/commit/55643deb4ad83a97b785ab0e840367f7f69c5fab))
* Total column was 0 for all device groups ([e15c8fb](https://github.com/mrichardson03/panos-ips-reports/commit/e15c8fba136ebb34ccf2ca4e3e052c1200de24b6))
