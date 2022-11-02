/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.hadoop.ozone.shell;

import org.apache.hadoop.hdds.cli.GenericCli;
import org.apache.hadoop.ozone.om.exceptions.OMException;

/**
 * Ozone user interface commands.
 * <p>
 * This class uses dispatch method to make calls
 * to appropriate handlers that execute the ozone functions.
 */
public abstract class Shell extends GenericCli {

  public static final String OZONE_URI_DESCRIPTION = "Ozone URI could either " +
      "be a full URI or short URI.\n" +
      "Full URI should start with o3:// followed by the OM host name or the " +
      "service id and can optionally also contain the port number. " +
      "Service id provides a logical name for multiple hosts. " +
      "It is defined in ozone.om.service.ids and later resolved as an " +
      "exact host through the property: " +
      "ozone.om.address.<serviceID>.<nodeID>=host. " +
      "Example of a full URI with host name for a key:" +
      "\no3://omhostname/vol1/bucket1/key1\n" +
      "With a service id and port number for a volume:" +
      "\no3://omserviceid:9862/vol1/\n" +
      "Short URI should start from the volume.\n" +
      "Example of a short URI for a bucket:\nvol1/bucket1\n" +
      "Unspecified information will be identified from the config files.";

  public Shell() {
  }

  public Shell(Class<?> type) {
    super(type);
  }

  @Override
  protected void printError(Throwable errorArg) {
    OMException omException = null;

    if (errorArg instanceof OMException) {
      omException = (OMException) errorArg;
    } else if (errorArg.getCause() instanceof OMException) {
      // If the OMException occurred in a method that could not throw a
      // checked exception (like an Iterator implementation), it will be
      // chained to an unchecked exception and thrown.
      omException = (OMException) errorArg.getCause();
    }

    if (omException != null && !isVerbose()) {
      // In non-verbose mode, reformat OMExceptions as error messages to the
      // user.
      System.err.println(String.format("%s %s", omException.getResult().name(),
              omException.getMessage()));
    } else {
      // Prints the stack trace when in verbose mode.
      super.printError(errorArg);
    }
  }
}

