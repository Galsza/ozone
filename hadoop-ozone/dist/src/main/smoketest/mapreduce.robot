# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
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
Documentation       Execute MR jobs
Library             OperatingSystem
Resource            commonlib.robot
Resource            lib/fs.robot
Test Timeout        4 minute


*** Variables ***
${SCHEME}          o3fs
${volume}          volume1
${bucket}          bucket1

*** Keywords ***
Find example jar
                    ${jar} =            Execute                 find /opt/hadoop/share/hadoop/mapreduce/ -name "*.jar" | grep mapreduce-examples | grep -v sources | grep -v test
                    [return]            ${jar}

*** Test cases ***
Certificate rotation test
                        ${exampleJar}    Find example jar
    ${root} =           Format FS URL    ${SCHEME}    ${volume}    ${bucket}
    ${inputdir} =       Format FS URL    ${SCHEME}    ${volume}    ${bucket}   terainput/
    ${outputdir} =      Format FS URL    ${SCHEME}    ${volume}    ${bucket}   teraoutput/
    ${validatedir} =    Format FS URL    ${SCHEME}    ${volume}    ${bucket}   teraresult/

                        #generate 100 megabytes of input for terasort
                        Execute                         yarn jar ${exampleJar} teragen -D fs.defaultFS=${root} 10m ${inputdir}
                        Execute                         yarn jar ${exampleJar} terasort -D fs.defaultFS=${root} ${inputdir} ${outputdir}
