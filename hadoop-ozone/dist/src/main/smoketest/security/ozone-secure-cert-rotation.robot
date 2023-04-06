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
Documentation       Test operations during certificate rotation
Library             OperatingSystem
Library             String
Library             BuiltIn
Resource            ../commonlib.robot
Resource            ../lib/fs.robot
Test Timeout        5 minutes

*** Variables ***
${SCHEME}          o3fs
${volume}          volume1
${bucket}          bucket1

*** Keywords ***
Find example jar
    ${jar} =            Execute             find /opt/hadoop/share/hadoop/mapreduce/ -name "*.jar" | grep mapreduce-examples | grep -v sources | grep -v test
                        [return]            ${jar}

*** Test Cases ***
Certificate rotation test
    ${exampleJar}       Find example jar
    ${root} =           Format FS URL    ${SCHEME}    ${volume}    ${bucket}
    ${inputdir} =       Format FS URL    ${SCHEME}    ${volume}    ${bucket}   input/
    ${outputdir} =      Format FS URL    ${SCHEME}    ${volume}    ${bucket}   output/
    ${validatedir} =    Format FS URL    ${SCHEME}    ${volume}    ${bucket}   validate/

                        #generate 100 megabytes of input for terasort
                        Execute                         hadoop jar ${exampleJar} teragen `expr 1024 \* 1024 \* 100` ${inputdir}
                        Execute                         hadoop jar ${exampleJar} terasort `expr 1024 \* 1024 \* 100` ${inputdir} ${outputdir}
                        Exucute                         hadoop jar ${exampleJar} teravalidate ${outputdir} ${validatedir}
    ${problems} =       Count Items In Directory        ${validatedir}
                        Should Be Equal As Integers     ${problems}    0


