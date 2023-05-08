# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

*** Settings ***
Documentation       Smoketest ozone cluster startup
Library             OperatingSystem
Resource            ../commonlib.robot
Resource            ../ozone-lib/freon.robot
Suite Setup         Setup Test
Test Timeout        5 minutes

*** Variables ***
${datanode}    datanode
${port}        9859

*** Keywords ***
Setup Test
    Run Keyword if    '${SECURITY_ENABLED}' == 'true'    Kinit test user     testuser     testuser.keytab

Test datanode functions before and after certificate rotation
    Basic key generation and validation
    ${sleepTime} =    Find wait time
    ${certId1} =      Get datanode cert serial
    Sleep	       ${sleepTime}
    Basic key generation and validation
    ${certId2} =        Get datanode cert serial
    Should Not Be Equal     ${certId1}      ${certId2}

Basic key generation and validation
    ${random} =   Generate Random String    10
    Freon OCKG    prefix=${random}
    Freon OCKV    prefix=${random}

Find wait time
    ${waitTime} =       Execute       printenv | grep hdds.x509.default.duration | sed 's/OZONE-SITE.XML_hdds.x509.default.duration=//' | sed 's/PT//'
    ${result} =       Set Variable if    "${waitTime}" != "${EMPTY}"      ${waitTime}    0s
    [return]            ${result}

Get datanode cert serial
    ${certSerial}       Execute     openssl s_client -connect "${datanode}":"${port}" -showcerts | openssl x509 -noout -serial | grep serial | sed 's/serial=//'
    [return]            ${certSerial}

*** Test Cases ***
Certificate rotation test
    Test datanode functions before and after certificate rotation

