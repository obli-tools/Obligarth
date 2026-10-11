// =============================================================================
// Catalog of the Apple schemas of the pilot's types (docs: modele-donnees-mdm
// §7.3): generated from the apple/device-management repository (release branch,
// commit 09f249a06e7e3289930bf6d05f38fb562f748ebf) until the editor's import chain (CFG-01)
// replaces it: keys, types, bounds and OS support only. Do not edit by hand.
//
// The schema of apple/device-management is distributed under this license:
//
// Copyright © 2022-2026 Apple Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// =============================================================================
import type { AppleSchemaCatalog } from '@obligarth/shared';

export const APPLE_SCHEMA_NOTICE = "Derived from the apple/device-management schema (MIT License). Copyright © 2022-2026 Apple Inc.";

export const APPLE_MVP_CATALOG: AppleSchemaCatalog = {
 "release": {
  "ref": "release",
  "commit": "09f249a06e7e3289930bf6d05f38fb562f748ebf",
  "importedAt": "2026-10-03"
 },
 "entries": {
  "com.apple.app.lock": {
   "type": "com.apple.app.lock",
   "family": "profile_payload",
   "title": "App Lock",
   "os": {
    "iOS": {
     "introduced": "6.0",
     "supervised": true,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a"
    },
    "tvOS": {
     "introduced": "10.2",
     "supervised": true
    },
    "visionOS": {
     "introduced": "n/a"
    },
    "watchOS": {
     "introduced": "n/a"
    }
   },
   "multiple": false,
   "keys": [
    {
     "name": "App",
     "title": "App",
     "type": "dictionary",
     "required": true,
     "subkeys": [
      {
       "name": "Identifier",
       "title": "Identifier",
       "type": "string",
       "required": true
      },
      {
       "name": "Options",
       "title": "Options",
       "type": "dictionary",
       "os": {
        "iOS": {
         "introduced": "7.0"
        }
       },
       "subkeys": [
        {
         "name": "DisableTouch",
         "title": "Disable touch",
         "type": "boolean"
        },
        {
         "name": "DisableDeviceRotation",
         "title": "Disable device rotation",
         "type": "boolean",
         "os": {
          "tvOS": {
           "introduced": "n/a"
          }
         }
        },
        {
         "name": "DisableVolumeButtons",
         "title": "Disable volume buttons",
         "type": "boolean",
         "os": {
          "tvOS": {
           "introduced": "n/a"
          }
         }
        },
        {
         "name": "DisableRingerSwitch",
         "title": "Disable ringer switch",
         "type": "boolean",
         "os": {
          "tvOS": {
           "introduced": "n/a"
          }
         }
        },
        {
         "name": "DisableSleepWakeButton",
         "title": "Disable sleep wake button",
         "type": "boolean",
         "os": {
          "tvOS": {
           "introduced": "n/a"
          }
         }
        },
        {
         "name": "DisableAutoLock",
         "title": "Disable auto lock",
         "type": "boolean"
        },
        {
         "name": "EnableVoiceOver",
         "title": "Enable VoiceOver",
         "type": "boolean"
        },
        {
         "name": "EnableZoom",
         "title": "Enable Zoom",
         "type": "boolean"
        },
        {
         "name": "EnableInvertColors",
         "title": "Enable Invert Colors",
         "type": "boolean"
        },
        {
         "name": "EnableAssistiveTouch",
         "title": "Enable AssistiveTouch",
         "type": "boolean",
         "os": {
          "tvOS": {
           "introduced": "n/a"
          }
         }
        },
        {
         "name": "EnableSpeakSelection",
         "title": "Enable Speak Selection",
         "type": "boolean",
         "os": {
          "tvOS": {
           "introduced": "n/a"
          }
         }
        },
        {
         "name": "EnableMonoAudio",
         "title": "Enable Mono Audio",
         "type": "boolean",
         "os": {
          "tvOS": {
           "introduced": "n/a"
          }
         }
        },
        {
         "name": "EnableVoiceControl",
         "title": "Enable Voice Control",
         "type": "boolean",
         "os": {
          "iOS": {
           "introduced": "13.0"
          },
          "tvOS": {
           "introduced": "n/a"
          }
         }
        }
       ]
      },
      {
       "name": "UserEnabledOptions",
       "title": "User enabled options",
       "type": "dictionary",
       "os": {
        "iOS": {
         "introduced": "7.0"
        }
       },
       "subkeys": [
        {
         "name": "VoiceControl",
         "title": "Voice Control",
         "type": "boolean",
         "os": {
          "iOS": {
           "introduced": "13.0"
          },
          "tvOS": {
           "introduced": "n/a"
          }
         }
        },
        {
         "name": "VoiceOver",
         "title": "VoiceOver",
         "type": "boolean"
        },
        {
         "name": "Zoom",
         "title": "Zoom",
         "type": "boolean"
        },
        {
         "name": "InvertColors",
         "title": "Invert Colors",
         "type": "boolean"
        },
        {
         "name": "AssistiveTouch",
         "title": "AssistiveTouch",
         "type": "boolean",
         "os": {
          "tvOS": {
           "introduced": "n/a"
          }
         }
        }
       ]
      }
     ]
    }
   ]
  },
  "com.apple.applicationaccess": {
   "type": "com.apple.applicationaccess",
   "family": "profile_payload",
   "title": "Restrictions",
   "os": {
    "iOS": {
     "introduced": "4.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "10.7",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "9.0",
     "supervised": false
    },
    "visionOS": {
     "introduced": "1.1",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "10.0",
     "supervised": false
    }
   },
   "multiple": true,
   "keys": [
    {
     "name": "allowAccountModification",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "supervised": true
      }
     }
    },
    {
     "name": "allowActivityContinuation",
     "title": "Allow handoff",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.15",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAddingGameCenterFriends",
     "title": "Allow adding Game Center friends",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "4.2.1",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAirDrop",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAirPlayIncomingRequests",
     "title": "Allow incoming AirPlay requests",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "12.3",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "10.2",
       "supervised": true
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAirPrint",
     "title": "Allow AirPrint",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAirPrintCredentialsStorage",
     "title": "Allow storage of AirPrint credentials in keychain",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAirPrintiBeaconDiscovery",
     "title": "Allow discovery of AirPrint printers using iBeacons",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAppCellularDataModification",
     "title": "Allow modifying cellular data usage for apps settings",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAppClips",
     "title": "Allow App Clips",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "14.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAppInstallation",
     "title": "Allow app installation",
     "type": "boolean",
     "os": {
      "iOS": {
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "supervised": true
      }
     }
    },
    {
     "name": "allowAppleIntelligenceReport",
     "title": "Allow Apple Intelligence report",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.4",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowApplePersonalizedAdvertising",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "12.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAppRemoval",
     "title": "Allow app removal",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "4.2.1",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "supervised": true
      }
     }
    },
    {
     "name": "allowAppsToBeHidden",
     "title": "Allow hiding apps",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAppsToBeLocked",
     "title": "Allow locking apps",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowARDRemoteManagementModification",
     "title": "Allow modifying Remote Management Sharing setting",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAssistant",
     "title": "Allow Siri",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "5.0",
       "deprecated": "26.4"
      },
      "macOS": {
       "introduced": "14.0",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "deprecated": "26.4"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAssistantUserGeneratedContent",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "deprecated": "26.4",
       "supervised": true
      }
     }
    },
    {
     "name": "allowAssistantWhileLocked",
     "title": "Allow Siri while locked",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "5.1",
       "deprecated": "26.4"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "deprecated": "26.4"
      }
     }
    },
    {
     "name": "allowAutoCorrection",
     "title": "Allow auto correction",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.1.3",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAutoDim",
     "title": "Allow auto dim",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "17.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAutomaticAppDownloads",
     "title": "Allow automatic app downloads",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "supervised": true
      }
     }
    },
    {
     "name": "allowAutomaticScreenSaver",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "15.4",
       "supervised": true
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowAutoUnlock",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "14.5",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.12",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowBluetoothModification",
     "title": "Allow modifying Bluetooth settings",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "13.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "27.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowBluetoothSharingModification",
     "title": "Allow modifying Bluetooth sharing setting",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowBookstore",
     "title": "Allow Book Store",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "6.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowBookstoreErotica",
     "title": "Allow Book Store erotica",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "6.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "11.3",
       "deprecated": "17.0"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCallRecording",
     "title": "Allow call recording",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.1",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "26.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCamera",
     "title": "Allow camera use",
     "type": "boolean",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.11",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "17.0"
      },
      "visionOS": {
       "introduced": "2.0",
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCellularPlanModification",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowChat",
     "title": "Allow use of iMessage",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "5.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "27.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudAddressBook",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.12",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudBackup",
     "title": "Allow iCloud backup",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "5.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudBookmarks",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.12",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudCalendar",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.12",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudDesktopAndDocuments",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.12.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudDocumentSync",
     "title": "Allow iCloud document sync",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "5.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.11",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudFreeform",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudKeychainSync",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.12",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudMail",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.12",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudNotes",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.12",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudPhotoLibrary",
     "title": "Allow iCloud photo library",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.12",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudPrivateRelay",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "15.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "12.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowCloudReminders",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.12",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowContentCaching",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.13",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowContinuousPathKeyboard",
     "title": "Allow continuous path keyboard",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "13.0",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowDefaultBrowserModification",
     "title": "Allow default browser modification",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.2",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowDefaultCallingAppModification",
     "title": "Allow default calling app modification",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowDefaultMessagingAppModification",
     "title": "Allow default messaging app modification",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowDefinitionLookup",
     "title": "Allow definition lookup",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.1.3",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.11",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowDeviceNameModification",
     "title": "Allow modifying device name",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "11.0",
       "supervised": true
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowDeviceSleep",
     "title": "Allow device sleep",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "13.0",
       "supervised": true
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowDiagnosticSubmission",
     "title": "Allow diagnostic submission",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "6.0"
      },
      "macOS": {
       "introduced": "10.13"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0"
      }
     }
    },
    {
     "name": "allowDiagnosticSubmissionModification",
     "title": "Allow modifying diagnostics settings",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.3.2",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowDictation",
     "title": "Allow dictation",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "10.3",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowedCameraRestrictionBundleIDs",
     "title": "Allowed exceptions to camera restriction",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "26.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "bundleIDException",
       "title": "Bundle ID to be excepted",
       "type": "string"
      }
     ]
    },
    {
     "name": "allowedExternalIntelligenceWorkspaceIDs",
     "title": "Allowed external intelligence workspace IDs",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "18.3",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.3",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "allowedWorkspaceID",
       "title": "Allowed workspace ID",
       "type": "string"
      }
     ]
    },
    {
     "name": "allowEnablingRestrictions",
     "title": "Allow configuring restrictions or ScreenTime",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowEnterpriseAppTrust",
     "title": "Allow trusting enterprise apps",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowEnterpriseBookBackup",
     "title": "Allow enterprise books backup",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowEnterpriseBookMetadataSync",
     "title": "Allow enterprise books notes and highlights sync",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowEraseContentAndSettings",
     "title": "Allow erase all content and settings",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "12.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowESIMModification",
     "title": "Allow eSIM modification",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "12.1",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowESIMOutgoingTransfers",
     "title": "Allow eSIM outgoing transfers",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowExplicitContent",
     "title": "Allow explicit content",
     "type": "boolean",
     "os": {
      "iOS": {
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "11.3",
       "supervised": true
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowExternalIntelligenceIntegrations",
     "title": "Allow external intelligence integrations",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.2",
       "deprecated": "26.4",
       "userEnrollment": "allowed"
      },
      "macOS": {
       "introduced": "15.2",
       "deprecated": "26.4",
       "userEnrollment": "allowed"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.4",
       "deprecated": "26.4",
       "userEnrollment": "allowed"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowExternalIntelligenceIntegrationsSignIn",
     "title": "Allow external intelligence integrations sign-in",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.2",
       "deprecated": "26.4",
       "userEnrollment": "allowed"
      },
      "macOS": {
       "introduced": "15.2",
       "deprecated": "26.4",
       "userEnrollment": "allowed"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.4",
       "deprecated": "26.4",
       "userEnrollment": "allowed"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowFileSharingModification",
     "title": "Allow modifying file sharing setting",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowFilesNetworkDriveAccess",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "13.1",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowFilesUSBDriveAccess",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "13.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowFindMyDevice",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "13.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.15",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowFindMyFriends",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "13.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.15",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowFindMyFriendsModification",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowFingerprintForUnlock",
     "title": "Allow Touch ID to unlock device",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.12.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowFingerprintModification",
     "title": "Allow modifying Touch ID fingerprints",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.3",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowGameCenter",
     "title": "Allow Game Center",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "6.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowGenmoji",
     "title": "Allow Genmoji",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.0",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowGlobalBackgroundFetchWhenRoaming",
     "title": "Allow automatic sync while roaming",
     "type": "boolean",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowHostPairing",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowImagePlayground",
     "title": "Allow Image Playground",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.0",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowImageWand",
     "title": "Allow Image Wand",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.0",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowInAppPurchases",
     "title": "Allow in app purchases",
     "type": "boolean",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowInternetSharingModification",
     "title": "Allow modifying internet sharing setting",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowiPhoneMirroring",
     "title": "Allow iPhone mirroring",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowiPhoneWidgetsOnMac",
     "title": "Allow iPhone widget on Mac",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "17.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowiTunes",
     "title": "Allow use of iTunes",
     "type": "boolean",
     "os": {
      "iOS": {
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowiTunesFileSharing",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.13",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowKeyboardShortcuts",
     "title": "Allow keyboard shortcuts",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowListedAppBundleIDs",
     "title": "Allow listed apps",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "15.0",
       "deprecated": "27.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "15.0",
       "deprecated": "27.0",
       "supervised": true
      },
      "visionOS": {
       "introduced": "27.0",
       "deprecated": "27.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "appAllowlistedBundleID",
       "title": "Allow listed app",
       "type": "string"
      }
     ]
    },
    {
     "name": "allowLiveVoicemail",
     "title": "Allow live voicemail",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "17.2",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "26.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowLocalUserCreation",
     "title": "Allow creating users in System Settings",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowLockScreenControlCenter",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowLockScreenNotificationsView",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowLockScreenTodayView",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowMailPrivacyProtection",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "15.2",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowMailSmartReplies",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.4",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowMailSummary",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.1",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.1",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowManagedAppsCloudSync",
     "title": "Allow iCloud sync for managed apps",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowManagedToWriteUnmanagedContacts",
     "title": "Allow managed apps to write to managed contacts accounts",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "12.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowMarketplaceAppInstallation",
     "title": "Allow app installation from alternative marketplaces",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "17.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowMediaSharingModification",
     "title": "Allow modifying Media Sharing setting",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "15.1",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowMultiplayerGaming",
     "title": "Allow multiplayer gaming",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "4.1",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowMusicService",
     "title": "Allow Apple Music",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.3",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.12",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowNews",
     "title": "Allow use of News",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowNFC",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "14.2",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowNotesTranscription",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.4",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowNotesTranscriptionSummary",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.3",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.3",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowNotificationsModification",
     "title": "Allow modifying notifications settings",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.3",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowOpenFromManagedToUnmanaged",
     "title": "Enable allow open from managed to unmanaged",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowOpenFromUnmanagedToManaged",
     "title": "Enable allow open from unmanaged to managed",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowOTAPKIUpdates",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPairedWatch",
     "title": "Allow pairing with Apple Watch",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPassbookWhileLocked",
     "title": "Allow Wallet while locked",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "6.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPasscodeModification",
     "title": "Allow modifying passcode",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPasswordAutoFill",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "12.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.14",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPasswordProximityRequests",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "12.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.14",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "12.0",
       "deprecated": "17.4",
       "removed": "26.4",
       "supervised": true
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPasswordSharing",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "12.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.14",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPersonalHotspotModification",
     "title": "Allow modifying personal hotspot settings",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "12.2",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPersonalizedHandwritingResults",
     "title": "Allow personalized handwriting results",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.0",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPhotoStream",
     "title": "Allow Photo Stream",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "5.0",
       "deprecated": "17.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPodcasts",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPredictiveKeyboard",
     "title": "Allow predictive keyboard",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.1.3",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowPrinterSharingModification",
     "title": "Allow modifying Printer Sharing setting",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowProximitySetupToNewDevice",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowRadioService",
     "title": "Allow iTunes radio",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.3",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowRapidSecurityResponseInstallation",
     "title": "Allow Background Security Improvements installation",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "16.0",
       "deprecated": "26.0",
       "removed": "27.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "13.0",
       "deprecated": "26.0",
       "removed": "27.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowRapidSecurityResponseRemoval",
     "title": "Allow Background Security Improvements removal",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "16.0",
       "deprecated": "26.0",
       "removed": "27.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "13.0",
       "deprecated": "26.0",
       "removed": "27.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowRCSMessaging",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.1",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowRemoteAppleEventsModification",
     "title": "Allow modifying remote Apple Events Sharing setting",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowRemoteAppPairing",
     "title": "Allow pairing with Remote app",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "10.2",
       "supervised": true
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowRemoteScreenObservation",
     "title": "Allow remote screen observation",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.3"
      },
      "macOS": {
       "introduced": "10.14.4"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowRosettaUsageAwareness",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowSafari",
     "title": "Allow use of Safari",
     "type": "boolean",
     "os": {
      "iOS": {
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowSafariHistoryClearing",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "26.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "26.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "26.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowSafariPrivateBrowsing",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "26.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "26.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "26.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowSafariSummary",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.4",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowSatelliteConnection",
     "title": "Allow use of satellite connectivity",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.2",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowScreenShot",
     "title": "Allow screenshots and screen recording",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "3.1"
      },
      "macOS": {
       "introduced": "10.14.4"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0"
      }
     }
    },
    {
     "name": "allowSharedDeviceTemporarySession",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "13.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowSharedStream",
     "title": "Allow shared stream",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "6.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowSiriAI",
     "title": "Allow Siri Apple Intelligence integration",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "27.0",
       "deprecated": "27.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowSpellCheck",
     "title": "Allow spell check",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.1.3",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowSpotlightInternetResults",
     "title": "Allow Siri suggestions",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.11",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowStartupDiskModification",
     "title": "Allow modifying startup disk settings",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowSystemAppRemoval",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowTimeMachineBackup",
     "title": "Allow modifying Time Machine settings",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowUIAppInstallation",
     "title": "Allow app installation from app store",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "supervised": true
      }
     }
    },
    {
     "name": "allowUIConfigurationProfileInstallation",
     "title": "Allow UI configuration profile installation",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "6.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "13.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowUniversalControl",
     "title": "Allow Universal Control",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "13.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowUnmanagedToReadManagedContacts",
     "title": "Allow unmanaged apps to read managed contacts accounts",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "12.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowUnpairedExternalBootToRecovery",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "14.5",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowUntrustedTLSPrompt",
     "title": "Allow user to accept untrusted TLS certificates",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "5.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "1.1",
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowUSBRestrictedMode",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.4.1",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "13.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowVideoConferencing",
     "title": "Allow video conferencing",
     "type": "boolean",
     "os": {
      "iOS": {
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowVideoConferencingRemoteControl",
     "title": "Allow video conferencing remote control",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowVisualIntelligenceSummary",
     "title": "Allow visual intelligence summary",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.3",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowVoiceDialing",
     "title": "Allow voice dialing while device is locked",
     "type": "boolean",
     "os": {
      "iOS": {
       "deprecated": "17.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowVPNCreation",
     "title": "Allow adding VPN configurations (supervised devices only)",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowWallpaperModification",
     "title": "Allow modifying wallpaper",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowWebDistributionAppInstallation",
     "title": "Allow app installation from web sites",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "17.5",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "allowWritingTools",
     "title": "Allow writing tools",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.0",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.4",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "autonomousSingleAppModePermittedAppIDs",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "appAutonomousSingleAppModePermittedID",
       "title": "Apps allow list for autonomous single app mode",
       "type": "string"
      }
     ]
    },
    {
     "name": "blacklistedAppBundleIDs",
     "title": "Blacklisted apps",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "9.3",
       "deprecated": "15.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "11.0",
       "deprecated": "15.0",
       "supervised": true
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "appBlacklistedBundleID",
       "title": "Blacklisted app",
       "type": "string"
      }
     ]
    },
    {
     "name": "blockedAppBundleIDs",
     "title": "Blocked apps",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "15.0",
       "deprecated": "27.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "15.0",
       "deprecated": "27.0",
       "supervised": true
      },
      "visionOS": {
       "introduced": "27.0",
       "deprecated": "27.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "appBlockedBundleID",
       "title": "Blocked app",
       "type": "string"
      }
     ]
    },
    {
     "name": "deniedICCIDsForiMessageFaceTime",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "26.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "deniedICCIDForiMessageFaceTime",
       "title": "Denied ICCID for iMessage and FaceTime",
       "type": "string"
      }
     ]
    },
    {
     "name": "deniedICCIDsForRCS",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "26.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "deniedICCIDForRCS",
       "title": "Denied ICCID for RCS",
       "type": "string"
      }
     ]
    },
    {
     "name": "enforcedFingerprintTimeout",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "12.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "enforcedSoftwareUpdateDelay",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "11.3",
       "deprecated": "26.0",
       "removed": "27.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13.4",
       "deprecated": "26.0",
       "removed": "27.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "12.2",
       "deprecated": "26.0",
       "removed": "27.0",
       "supervised": true
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "range": {
      "min": 1,
      "max": 90
     }
    },
    {
     "name": "enforcedSoftwareUpdateMajorOSDeferredInstallDelay",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "11.3",
       "deprecated": "26.0",
       "removed": "27.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "range": {
      "min": 1,
      "max": 90
     }
    },
    {
     "name": "enforcedSoftwareUpdateMinorOSDeferredInstallDelay",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "11.3",
       "deprecated": "26.0",
       "removed": "27.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "range": {
      "min": 1,
      "max": 90
     }
    },
    {
     "name": "enforcedSoftwareUpdateNonOSDeferredInstallDelay",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "11.3",
       "deprecated": "26.0",
       "removed": "27.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "range": {
      "min": 1,
      "max": 90
     }
    },
    {
     "name": "forceAirDropUnmanaged",
     "title": "Treat AirDrop as unmanaged destination",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "9.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceAirPlayIncomingRequestsPairingPassword",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceAirPlayOutgoingRequestsPairingPassword",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.1"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceAirPrintTrustedTLSRequirement",
     "title": "Disallow AirPrint to destinations with untrusted certificates",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceAssistantProfanityFilter",
     "title": "Enable Siri profanity filter",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "5.0",
       "deprecated": "26.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13",
       "deprecated": "26.4",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceAuthenticationBeforeAutoFill",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceAutomaticDateAndTime",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "12.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "12.2",
       "supervised": true
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceBypassScreenCaptureAlert",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "15.1",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceClassroomAutomaticallyJoinClasses",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.14.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceClassroomRequestPermissionToLeaveClasses",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.3",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.14.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceClassroomUnpromptedAppAndDeviceLock",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.14.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceClassroomUnpromptedScreenObservation",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.14.4",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceDelayedAppSoftwareUpdates",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "11.0",
       "deprecated": "26.0",
       "removed": "27.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceDelayedMajorSoftwareUpdates",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "11.3",
       "deprecated": "26.0",
       "removed": "27.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceDelayedSoftwareUpdates",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "11.3",
       "deprecated": "26.0",
       "removed": "27.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13",
       "deprecated": "26.0",
       "removed": "27.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "12.2",
       "deprecated": "26.0",
       "removed": "27.0",
       "supervised": true
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceEncryptedBackup",
     "title": "Force encrypted backups",
     "type": "boolean",
     "os": {
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceITunesStorePasswordEntry",
     "title": "Require iTunes password for all purchases",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "6.0",
       "deprecated": "17.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceLimitAdTracking",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceOnDeviceOnlyDictation",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "14.5",
       "deprecated": "26.4"
      },
      "macOS": {
       "introduced": "14.0",
       "deprecated": "26.4"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "deprecated": "26.4"
      },
      "watchOS": {
       "deprecated": "26.4"
      }
     }
    },
    {
     "name": "forceOnDeviceOnlyTranslation",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "15.0",
       "deprecated": "26.4"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "deprecated": "26.4"
      }
     }
    },
    {
     "name": "forcePreserveESIMOnErase",
     "title": "Force preserve ESIM on erase",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "17.2",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceWatchWristDetection",
     "title": "Force Apple Watch wrist detection",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "8.2"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceWiFiPowerOn",
     "title": "Disallow Wi-Fi from being turned off",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "13.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceWiFiToAllowedNetworksOnly",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "14.5",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "forceWiFiWhitelisting",
     "title": "Only join Wi-Fi networks installed by profiles",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "10.3",
       "deprecated": "14.5",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "ratingApps",
     "title": "Apps ranking number",
     "type": "integer",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "11.3"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "range": {
      "min": 0,
      "max": 1000
     }
    },
    {
     "name": "ratingAppsExemptedBundleIDs",
     "title": "Apps exempted from rating restrictions",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "26.1",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "ratingAppsExemptedBundleID",
       "title": "Exempted app",
       "type": "string"
      }
     ]
    },
    {
     "name": "ratingMovies",
     "title": "Movies ranking number",
     "type": "integer",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "11.3"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "range": {
      "min": 0,
      "max": 1000
     }
    },
    {
     "name": "ratingRegion",
     "title": "Region code",
     "type": "string",
     "os": {
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "rangelist": [
      "us",
      "au",
      "ca",
      "de",
      "fr",
      "ie",
      "jp",
      "nz",
      "gb"
     ]
    },
    {
     "name": "ratingTVShows",
     "title": "TV shows ranking number",
     "type": "integer",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "11.3"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "range": {
      "min": 0,
      "max": 1000
     }
    },
    {
     "name": "requireManagedPasteboard",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "15.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "safariAcceptCookies",
     "title": "Accept cookies in Safari",
     "type": "real",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "rangelist": [
      0,
      1,
      1.5,
      2
     ]
    },
    {
     "name": "safariAllowAutoFill",
     "title": "Allow AutoFill in Safari",
     "type": "boolean",
     "os": {
      "iOS": {
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "10.13",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "safariAllowJavaScript",
     "title": "Allow JavaScript",
     "type": "boolean",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "safariAllowPopups",
     "title": "Allow pop-ups",
     "type": "boolean",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "safariForceFraudWarning",
     "title": "Enable fraud warning",
     "type": "boolean",
     "os": {
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "whitelistedAppBundleIDs",
     "title": "Whitelisted apps",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "9.3",
       "deprecated": "15.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "11.0",
       "deprecated": "15.0",
       "supervised": true
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "appWhitelistedBundleID",
       "title": "Whitelisted app",
       "type": "string"
      }
     ]
    }
   ]
  },
  "com.apple.configuration.passcode.settings": {
   "type": "com.apple.configuration.passcode.settings",
   "family": "declaration",
   "title": "Passcode:Settings",
   "os": {
    "iOS": {
     "introduced": "15.0",
     "enrollments": [
      "supervised",
      "device",
      "user",
      "local"
     ],
     "scopes": [
      "system"
     ]
    },
    "macOS": {
     "introduced": "13.0",
     "enrollments": [
      "supervised",
      "local"
     ],
     "scopes": [
      "system",
      "user"
     ]
    },
    "tvOS": {
     "introduced": "n/a"
    },
    "visionOS": {
     "introduced": "2.0",
     "enrollments": [
      "supervised",
      "device",
      "user",
      "local"
     ],
     "scopes": [
      "system"
     ]
    },
    "watchOS": {
     "introduced": "10.0",
     "enrollments": [
      "supervised",
      "local"
     ],
     "scopes": [
      "system"
     ]
    }
   },
   "apply": "combined",
   "keys": [
    {
     "name": "RequirePasscode",
     "title": "Require passcode on device",
     "type": "boolean"
    },
    {
     "name": "RequireAlphanumericPasscode",
     "title": "Require alphanumeric passcode",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "16.2"
      },
      "macOS": {
       "introduced": "13.1"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "RequireComplexPasscode",
     "title": "Require complex passcode",
     "type": "boolean"
    },
    {
     "name": "MinimumLength",
     "title": "Minimum passcode length",
     "type": "integer",
     "range": {
      "min": 0,
      "max": 16
     }
    },
    {
     "name": "MinimumComplexCharacters",
     "title": "Minimum complex characters",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "16.2"
      },
      "macOS": {
       "introduced": "13.1"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "range": {
      "min": 0,
      "max": 4
     }
    },
    {
     "name": "MaximumFailedAttempts",
     "title": "Maximum number of failed attempts",
     "type": "integer",
     "range": {
      "min": 2,
      "max": 11
     }
    },
    {
     "name": "FailedAttemptsResetInMinutes",
     "title": "Failed attempts reset",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "13.1"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "MaximumGracePeriodInMinutes",
     "title": "Maximum grace period",
     "type": "integer"
    },
    {
     "name": "MaximumInactivityInMinutes",
     "title": "Automatic device lock",
     "type": "integer",
     "range": {
      "min": 0,
      "max": 15
     }
    },
    {
     "name": "MaximumPasscodeAgeInDays",
     "title": "Maximum passcode age",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "16.2"
      },
      "macOS": {
       "introduced": "13.1"
      }
     },
     "range": {
      "min": 0,
      "max": 730
     }
    },
    {
     "name": "PasscodeReuseLimit",
     "title": "Passcode reuse limit",
     "type": "integer",
     "range": {
      "min": 1,
      "max": 50
     }
    },
    {
     "name": "ChangeAtNextAuth",
     "title": "Change at next auth",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "13.1"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "CustomRegex",
     "title": "Custom regex",
     "type": "dictionary",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "Regex",
       "type": "string",
       "required": true
      },
      {
       "name": "Description",
       "title": "Description",
       "type": "dictionary",
       "subkeys": [
        {
         "name": "ANY",
         "type": "string"
        }
       ]
      }
     ]
    }
   ]
  },
  "com.apple.configuration.softwareupdate.enforcement.specific": {
   "type": "com.apple.configuration.softwareupdate.enforcement.specific",
   "family": "declaration",
   "title": "Software Update:Enforcement:Specific",
   "os": {
    "iOS": {
     "introduced": "17.0",
     "enrollments": [
      "supervised",
      "device"
     ],
     "scopes": [
      "system"
     ]
    },
    "macOS": {
     "introduced": "14.0",
     "enrollments": [
      "supervised"
     ],
     "scopes": [
      "system"
     ]
    },
    "tvOS": {
     "introduced": "18.4",
     "enrollments": [
      "supervised",
      "device"
     ],
     "scopes": [
      "system"
     ]
    },
    "visionOS": {
     "introduced": "26.0",
     "enrollments": [
      "supervised",
      "device"
     ],
     "scopes": [
      "system"
     ]
    },
    "watchOS": {
     "introduced": "n/a"
    }
   },
   "apply": "multiple",
   "keys": [
    {
     "name": "TargetOSVersion",
     "title": "Target OS version",
     "type": "string",
     "required": true
    },
    {
     "name": "TargetBuildVersion",
     "title": "Target build version",
     "type": "string"
    },
    {
     "name": "TargetLocalDateTime",
     "title": "Target local date time",
     "type": "string",
     "required": true
    },
    {
     "name": "DetailsURL",
     "title": "Details URL",
     "type": "string"
    }
   ]
  },
  "com.apple.configuration.softwareupdate.settings": {
   "type": "com.apple.configuration.softwareupdate.settings",
   "family": "declaration",
   "title": "Software Update:Settings",
   "os": {
    "iOS": {
     "introduced": "18.0",
     "enrollments": [
      "supervised",
      "device"
     ],
     "scopes": [
      "system"
     ]
    },
    "macOS": {
     "introduced": "15.0",
     "enrollments": [
      "supervised"
     ],
     "scopes": [
      "system"
     ]
    },
    "tvOS": {
     "introduced": "18.4",
     "enrollments": [
      "supervised",
      "device"
     ],
     "scopes": [
      "system"
     ]
    },
    "visionOS": {
     "introduced": "26.0",
     "enrollments": [
      "supervised",
      "device"
     ],
     "scopes": [
      "system"
     ]
    },
    "watchOS": {
     "introduced": "n/a"
    }
   },
   "apply": "combined",
   "keys": [
    {
     "name": "Notifications",
     "title": "Software update notifications",
     "type": "boolean"
    },
    {
     "name": "Deferrals",
     "title": "Software update deferrals",
     "type": "dictionary",
     "os": {
      "iOS": {
       "enrollments": [
        "supervised"
       ]
      },
      "tvOS": {
       "enrollments": [
        "supervised"
       ]
      },
      "visionOS": {
       "enrollments": [
        "supervised"
       ]
      }
     },
     "subkeys": [
      {
       "name": "CombinedPeriodInDays",
       "title": "Combined major/minor update deferral period",
       "type": "integer",
       "os": {
        "macOS": {
         "introduced": "n/a"
        }
       },
       "range": {
        "min": 1,
        "max": 90
       }
      },
      {
       "name": "MajorPeriodInDays",
       "title": "Major update deferral period",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "n/a"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "n/a"
        }
       },
       "range": {
        "min": 1,
        "max": 90
       }
      },
      {
       "name": "MinorPeriodInDays",
       "title": "Minor update deferral period",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "n/a"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "n/a"
        }
       },
       "range": {
        "min": 1,
        "max": 90
       }
      },
      {
       "name": "SystemPeriodInDays",
       "title": "System update deferral period",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "n/a"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "n/a"
        }
       },
       "range": {
        "min": 1,
        "max": 90
       }
      }
     ]
    },
    {
     "name": "RecommendedCadence",
     "title": "Software update recommended cadence",
     "type": "string",
     "os": {
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      }
     },
     "rangelist": [
      "All",
      "Oldest",
      "Newest"
     ]
    },
    {
     "name": "AutomaticActions",
     "title": "Automatic software update settings",
     "type": "dictionary",
     "os": {
      "iOS": {
       "enrollments": [
        "supervised"
       ]
      },
      "tvOS": {
       "enrollments": [
        "supervised"
       ]
      },
      "visionOS": {
       "enrollments": [
        "supervised"
       ]
      }
     },
     "subkeys": [
      {
       "name": "Download",
       "title": "Automatic downloads of available updates.",
       "type": "string",
       "os": {
        "tvOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        "Allowed",
        "AlwaysOn",
        "AlwaysOff"
       ]
      },
      {
       "name": "InstallOSUpdates",
       "title": "Automatic installs of OS updates.",
       "type": "string",
       "rangelist": [
        "Allowed",
        "AlwaysOn",
        "AlwaysOff"
       ]
      },
      {
       "name": "InstallSecurityUpdate",
       "title": "Automatic installs of available security updates.",
       "type": "string",
       "os": {
        "tvOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        "Allowed",
        "AlwaysOn",
        "AlwaysOff"
       ]
      }
     ]
    },
    {
     "name": "RapidSecurityResponse",
     "title": "Background Security Improvements settings",
     "type": "dictionary",
     "os": {
      "iOS": {
       "enrollments": [
        "supervised"
       ]
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "Enable",
       "title": "Enable Background Security Improvements installation",
       "type": "boolean"
      },
      {
       "name": "EnableRollback",
       "title": "Enable Background Security Improvements rollbacks",
       "type": "boolean"
      }
     ]
    },
    {
     "name": "AllowStandardUserOSUpdates",
     "title": "Allow standard user OS updates",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "Beta",
     "title": "Beta",
     "type": "dictionary",
     "os": {
      "macOS": {
       "introduced": "15.4",
       "enrollments": [
        "supervised"
       ],
       "scopes": [
        "system"
       ]
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "ProgramEnrollment",
       "title": "Program enrollment",
       "type": "string",
       "os": {
        "iOS": {
         "enrollments": [
          "supervised"
         ]
        }
       },
       "rangelist": [
        "Allowed",
        "AlwaysOn",
        "AlwaysOff"
       ]
      },
      {
       "name": "OfferPrograms",
       "title": "Offer programs",
       "type": "array",
       "subkeys": [
        {
         "name": "Program",
         "title": "Program",
         "type": "dictionary",
         "required": true,
         "subkeys": [
          {
           "name": "Description",
           "title": "Description",
           "type": "string",
           "required": true
          },
          {
           "name": "Token",
           "title": "Token",
           "type": "string",
           "required": true
          }
         ]
        }
       ]
      },
      {
       "name": "RequireProgram",
       "title": "Require program",
       "type": "dictionary",
       "os": {
        "iOS": {
         "enrollments": [
          "supervised"
         ]
        }
       },
       "subkeys": [
        {
         "name": "Description",
         "title": "Description",
         "type": "string",
         "required": true
        },
        {
         "name": "Token",
         "title": "Token",
         "type": "string",
         "required": true
        }
       ]
      }
     ]
    }
   ]
  },
  "com.apple.homescreenlayout": {
   "type": "com.apple.homescreenlayout",
   "family": "profile_payload",
   "title": "Home Screen Layout",
   "os": {
    "iOS": {
     "introduced": "9.3",
     "supervised": true,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a"
    },
    "tvOS": {
     "introduced": "11.0",
     "supervised": true
    },
    "visionOS": {
     "introduced": "n/a"
    },
    "watchOS": {
     "introduced": "n/a"
    }
   },
   "multiple": false,
   "keys": [
    {
     "name": "Dock",
     "type": "array",
     "subkeys": [
      {
       "name": "IconItem",
       "type": "dictionary",
       "subkeys": [
        {
         "name": "Type",
         "type": "string",
         "required": true,
         "rangelist": [
          "Application",
          "Folder",
          "WebClip"
         ]
        },
        {
         "name": "DisplayName",
         "type": "string"
        },
        {
         "name": "BundleID",
         "type": "string"
        },
        {
         "name": "Pages",
         "type": "array",
         "subkeys": [
          {
           "name": "PagesItem",
           "type": "array",
           "subkeys": [
            {
             "name": "IconItem",
             "type": "dictionary",
             "subkeys": [
              {
               "name": "Type",
               "type": "string",
               "required": true,
               "rangelist": [
                "Application",
                "Folder",
                "WebClip"
               ]
              },
              {
               "name": "DisplayName",
               "type": "string"
              },
              {
               "name": "BundleID",
               "type": "string"
              },
              {
               "name": "Pages",
               "type": "array",
               "subkeys": [
                {
                 "name": "PagesItem",
                 "type": "array"
                }
               ]
              },
              {
               "name": "URL",
               "type": "string",
               "os": {
                "iOS": {
                 "introduced": "11.3"
                }
               }
              }
             ]
            }
           ]
          }
         ]
        },
        {
         "name": "URL",
         "type": "string",
         "os": {
          "iOS": {
           "introduced": "11.3"
          }
         }
        }
       ]
      }
     ]
    },
    {
     "name": "Pages",
     "type": "array",
     "required": true,
     "subkeys": [
      {
       "name": "PagesItem",
       "type": "array",
       "subkeys": [
        {
         "name": "IconItem",
         "type": "dictionary",
         "subkeys": [
          {
           "name": "Type",
           "type": "string",
           "required": true,
           "rangelist": [
            "Application",
            "Folder",
            "WebClip"
           ]
          },
          {
           "name": "DisplayName",
           "type": "string"
          },
          {
           "name": "BundleID",
           "type": "string"
          },
          {
           "name": "Pages",
           "type": "array",
           "subkeys": [
            {
             "name": "PagesItem",
             "type": "array",
             "subkeys": [
              {
               "name": "IconItem",
               "type": "dictionary",
               "subkeys": [
                {
                 "name": "Type",
                 "type": "string",
                 "required": true,
                 "rangelist": [
                  "Application",
                  "Folder",
                  "WebClip"
                 ]
                },
                {
                 "name": "DisplayName",
                 "type": "string"
                },
                {
                 "name": "BundleID",
                 "type": "string"
                },
                {
                 "name": "Pages",
                 "type": "array",
                 "subkeys": [
                  {
                   "name": "PagesItem",
                   "type": "array"
                  }
                 ]
                },
                {
                 "name": "URL",
                 "type": "string",
                 "os": {
                  "iOS": {
                   "introduced": "11.3"
                  }
                 }
                }
               ]
              }
             ]
            }
           ]
          },
          {
           "name": "URL",
           "type": "string",
           "os": {
            "iOS": {
             "introduced": "11.3"
            }
           }
          }
         ]
        }
       ]
      }
     ]
    }
   ]
  },
  "com.apple.security.pkcs1": {
   "type": "com.apple.security.pkcs1",
   "family": "profile_payload",
   "title": "Certificate (PKCS #1)",
   "os": {
    "iOS": {
     "introduced": "4.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "10.7",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "9.0",
     "supervised": false
    },
    "visionOS": {
     "introduced": "1.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "3.0"
    }
   },
   "multiple": true,
   "keys": [
    {
     "name": "PayloadCertificateFileName",
     "title": "Payload certificate filename",
     "type": "string"
    },
    {
     "name": "PayloadContent",
     "title": "Payload certificate data",
     "type": "data",
     "required": true
    }
   ]
  },
  "com.apple.security.pkcs12": {
   "type": "com.apple.security.pkcs12",
   "family": "profile_payload",
   "title": "Certificate (PKCS #12)",
   "os": {
    "iOS": {
     "introduced": "4.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "10.7",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "9.0",
     "supervised": false
    },
    "visionOS": {
     "introduced": "1.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "3.0"
    }
   },
   "multiple": true,
   "keys": [
    {
     "name": "PayloadCertificateFileName",
     "title": "Payload certificate filename",
     "type": "string"
    },
    {
     "name": "PayloadContent",
     "title": "Payload certificate data",
     "type": "data",
     "required": true
    },
    {
     "name": "Password",
     "title": "Password",
     "type": "string"
    },
    {
     "name": "AllowAllAppsAccess",
     "title": "Allow all apps access",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.10"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "KeyIsExtractable",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.15"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    }
   ]
  },
  "com.apple.security.root": {
   "type": "com.apple.security.root",
   "family": "profile_payload",
   "title": "Certificate (Root)",
   "os": {
    "iOS": {
     "introduced": "4.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "10.7",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "9.0",
     "supervised": false
    },
    "visionOS": {
     "introduced": "1.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "3.0"
    }
   },
   "multiple": true,
   "keys": [
    {
     "name": "PayloadCertificateFileName",
     "title": "Payload certificate filename",
     "type": "string"
    },
    {
     "name": "PayloadContent",
     "title": "Payload certificate data",
     "type": "data",
     "required": true
    }
   ]
  },
  "com.apple.shareddeviceconfiguration": {
   "type": "com.apple.shareddeviceconfiguration",
   "family": "profile_payload",
   "title": "Lock Screen Message",
   "os": {
    "iOS": {
     "introduced": "9.3",
     "supervised": true,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a"
    },
    "tvOS": {
     "introduced": "n/a"
    },
    "visionOS": {
     "introduced": "n/a"
    },
    "watchOS": {
     "introduced": "n/a"
    }
   },
   "multiple": false,
   "keys": [
    {
     "name": "AssetTagInformation",
     "title": "Asset tag",
     "type": "string"
    },
    {
     "name": "IfLostReturnToMessage",
     "title": "If lost message",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "9.3",
       "deprecated": "9.3.1"
      }
     }
    },
    {
     "name": "LockScreenFootnote",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "9.3.1"
      }
     }
    }
   ]
  },
  "com.apple.vpn.managed": {
   "type": "com.apple.vpn.managed",
   "family": "profile_payload",
   "title": "VPN",
   "os": {
    "iOS": {
     "introduced": "4.0",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "10.7",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "tvOS": {
     "introduced": "17.0",
     "supervised": false
    },
    "visionOS": {
     "introduced": "1.0",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "watchOS": {
     "introduced": "n/a"
    }
   },
   "multiple": true,
   "keys": [
    {
     "name": "VPNType",
     "title": "Type",
     "type": "string",
     "required": true,
     "rangelist": [
      "VPN",
      "L2TP",
      "IPSec",
      "IKEv2",
      "AlwaysOn",
      "TransparentProxy"
     ]
    },
    {
     "name": "VPNSubType",
     "title": "VPN subtype",
     "type": "string"
    },
    {
     "name": "UserDefinedName",
     "title": "User defined name",
     "type": "string",
     "required": true
    },
    {
     "name": "VendorConfig",
     "title": "Vendor configuration dictionary",
     "type": "dictionary",
     "subkeys": [
      {
       "name": "Realm",
       "title": "Realm",
       "type": "string"
      },
      {
       "name": "Role",
       "title": "Role",
       "type": "string"
      },
      {
       "name": "Group",
       "title": "Group",
       "type": "string"
      },
      {
       "name": "LoginGroupOrDomain",
       "title": "Login group or domain",
       "type": "string"
      }
     ]
    },
    {
     "name": "VPN",
     "title": "VPN",
     "type": "dictionary",
     "subkeys": [
      {
       "name": "AuthName",
       "title": "Account username",
       "type": "string"
      },
      {
       "name": "AuthPassword",
       "title": "Account password",
       "type": "string"
      },
      {
       "name": "RemoteAddress",
       "title": "RemoteAddress",
       "type": "string",
       "required": true
      },
      {
       "name": "AuthenticationMethod",
       "title": "Authentication method",
       "type": "string",
       "rangelist": [
        "Password",
        "Certificate",
        "Password+Certificate"
       ]
      },
      {
       "name": "PayloadCertificateUUID",
       "title": "Certificate UUID",
       "type": "string"
      },
      {
       "name": "ProviderBundleIdentifier",
       "title": "Provider bundle identifier",
       "type": "string"
      },
      {
       "name": "ProviderDesignatedRequirement",
       "title": "Provider designated requirement",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "n/a"
        },
        "macOS": {
         "introduced": "10.15"
        },
        "visionOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "DisconnectOnIdle",
       "title": "Enable disconnect on idle",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "DisconnectOnIdleTimer",
       "title": "Disconnect on idle time",
       "type": "integer"
      },
      {
       "name": "ProviderType",
       "type": "string",
       "rangelist": [
        "packet-tunnel",
        "app-proxy"
       ]
      },
      {
       "name": "IncludeAllNetworks",
       "title": "Include all networks",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "14.0"
        },
        "macOS": {
         "introduced": "10.15"
        },
        "tvOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "EnforceRoutes",
       "title": "Enforce routes",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "14.2"
        },
        "macOS": {
         "introduced": "11.0"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "ExcludeLocalNetworks",
       "title": "Exclude local networks",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "14.2"
        },
        "macOS": {
         "introduced": "10.15"
        },
        "tvOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "ExcludeCellularServices",
       "title": "Exclude cellular services",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "16.4"
        },
        "macOS": {
         "introduced": "13.3"
        },
        "tvOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "ExcludeAPNs",
       "title": "Exclude APNs",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "16.4"
        },
        "macOS": {
         "introduced": "13.3"
        },
        "tvOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "ExcludeDeviceCommunication",
       "title": "Exclude device communication",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "17.4"
        },
        "macOS": {
         "introduced": "14.4"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "1.1"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "OnDemandEnabled",
       "title": "Enable VPN on demand",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "OnDemandUserOverrideDisabled",
       "title": "Prevent users from toggling VPN on demand",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "14.0"
        },
        "macOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "OnDemandMatchDomainsAlways",
       "title": "On demand match domains always",
       "type": "array",
       "os": {
        "iOS": {
         "deprecated": "7.0"
        }
       },
       "subkeys": [
        {
         "name": "MatchDomainAlwaysElement",
         "title": "Match domain always element",
         "type": "string"
        }
       ]
      },
      {
       "name": "OnDemandMatchDomainsNever",
       "title": "On demand match domains never",
       "type": "array",
       "os": {
        "iOS": {
         "deprecated": "7.0"
        }
       },
       "subkeys": [
        {
         "name": "MatchDomainNeverElement",
         "title": "Match domain never element",
         "type": "string"
        }
       ]
      },
      {
       "name": "OnDemandMatchDomainsOnRetry",
       "title": "On demand match domains on retry",
       "type": "array",
       "os": {
        "iOS": {
         "deprecated": "7.0"
        }
       },
       "subkeys": [
        {
         "name": "MatchDomainOnRetryElement",
         "title": "Match domain on retry element",
         "type": "string"
        }
       ]
      },
      {
       "name": "OnDemandRules",
       "title": "On demand rules",
       "type": "array",
       "subkeys": [
        {
         "name": "OnDemandRulesElement",
         "title": "On demand rules element",
         "type": "dictionary",
         "subkeys": [
          {
           "name": "Action",
           "title": "On demand action",
           "type": "string",
           "required": true,
           "rangelist": [
            "Allow",
            "Connect",
            "Disconnect",
            "EvaluateConnection",
            "Ignore"
           ]
          },
          {
           "name": "ActionParameters",
           "title": "Action parameters",
           "type": "array",
           "subkeys": [
            {
             "name": "ActionParameter",
             "title": "Action parameter",
             "type": "dictionary",
             "subkeys": [
              {
               "name": "Domains",
               "title": "Domains",
               "type": "array",
               "required": true,
               "subkeys": [
                {
                 "name": "DomainsElement",
                 "title": "Domains element",
                 "type": "string"
                }
               ]
              },
              {
               "name": "DomainAction",
               "title": "Domain action",
               "type": "string",
               "required": true,
               "rangelist": [
                "ConnectIfNeeded",
                "NeverConnect"
               ]
              },
              {
               "name": "RequiredDNSServers",
               "title": "Required DNS servers",
               "type": "array",
               "subkeys": [
                {
                 "name": "RequiredDNSServersElement",
                 "title": "Required DNS servers element",
                 "type": "string"
                }
               ]
              },
              {
               "name": "RequiredURLStringProbe",
               "title": "Required URL string probe",
               "type": "string"
              }
             ]
            }
           ]
          },
          {
           "name": "DNSDomainMatch",
           "title": "DNS domain match",
           "type": "array",
           "subkeys": [
            {
             "name": "DNSDomainMatchElement",
             "title": "DNS domain match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "DNSServerAddressMatch",
           "title": "DNS server address match",
           "type": "array",
           "subkeys": [
            {
             "name": "DNSServerAddressMatchElement",
             "title": "DNS server address match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "InterfaceTypeMatch",
           "title": "Interface type match",
           "type": "string",
           "rangelist": [
            "Ethernet",
            "WiFi",
            "Cellular"
           ]
          },
          {
           "name": "SSIDMatch",
           "title": "SSID match",
           "type": "array",
           "subkeys": [
            {
             "name": "SSIDMatchElement",
             "title": "SSID match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "URLStringProbe",
           "title": "URL string probe",
           "type": "string"
          }
         ]
        }
       ]
      }
     ]
    },
    {
     "name": "IPv4",
     "title": "IPv4 settings",
     "type": "dictionary",
     "os": {
      "tvOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "OverridePrimary",
       "title": "Override primary connection",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      }
     ]
    },
    {
     "name": "PPP",
     "title": "PPP",
     "type": "dictionary",
     "os": {
      "tvOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "AuthName",
       "title": "Account username",
       "type": "string"
      },
      {
       "name": "AuthPassword",
       "title": "Account password",
       "type": "string"
      },
      {
       "name": "TokenCard",
       "title": "Use token card",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "CommRemoteAddress",
       "title": "Remote address",
       "type": "string"
      },
      {
       "name": "AuthEAPPlugins",
       "title": "EAP plugins",
       "type": "array",
       "subkeys": [
        {
         "name": "EAPPluginElement",
         "title": "EAP plugin",
         "type": "string",
         "rangelist": [
          "EAP-RSA",
          "EAP-TLS",
          "EAP-KRB"
         ]
        }
       ]
      },
      {
       "name": "AuthProtocol",
       "title": "Protocol",
       "type": "array",
       "subkeys": [
        {
         "name": "AuthProtocolElement",
         "title": "Auth protocol",
         "type": "string",
         "rangelist": [
          "EAP"
         ]
        }
       ]
      },
      {
       "name": "CCPMPPE40Enabled",
       "title": "Enable CCPMPPE40",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "CCPMPPE128Enabled",
       "title": "Enable CCPMPPE128",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "CCPEnabled",
       "title": "Enable CCP",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "DisconnectOnIdle",
       "title": "Enable disconnect on idle",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "DisconnectOnIdleTimer",
       "title": "Disconnect on idle time",
       "type": "integer"
      }
     ]
    },
    {
     "name": "IPSec",
     "title": "IPSec settings",
     "type": "dictionary",
     "os": {
      "tvOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "RemoteAddress",
       "title": "Remote address",
       "type": "string"
      },
      {
       "name": "AuthenticationMethod",
       "title": "Authentication method",
       "type": "string",
       "rangelist": [
        "SharedSecret",
        "Certificate"
       ]
      },
      {
       "name": "XAuthName",
       "title": "Username",
       "type": "string"
      },
      {
       "name": "XAuthPassword",
       "title": "Password",
       "type": "string"
      },
      {
       "name": "XAuthEnabled",
       "title": "XAUTH enabled",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "XAuthPasswordEncryption",
       "title": "XAUTH password encryption",
       "type": "string",
       "rangelist": [
        "Prompt"
       ]
      },
      {
       "name": "LocalIdentifier",
       "title": "Local identifier",
       "type": "string"
      },
      {
       "name": "LocalIdentifierType",
       "title": "Local identifier type",
       "type": "string",
       "rangelist": [
        "KeyID"
       ]
      },
      {
       "name": "SharedSecret",
       "title": "Shared secret",
       "type": "data"
      },
      {
       "name": "PayloadCertificateUUID",
       "title": "Certificate UUID",
       "type": "string"
      },
      {
       "name": "PromptForVPNPIN",
       "title": "Prompt for PIN",
       "type": "boolean"
      },
      {
       "name": "DisconnectOnIdle",
       "title": "Enable disconnect on idle",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "DisconnectOnIdleTimer",
       "title": "Disconnect on idle time",
       "type": "integer"
      },
      {
       "name": "OnDemandEnabled",
       "title": "Enable VPN on demand",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "OnDemandMatchDomainsAlways",
       "title": "On demand match domains always",
       "type": "array",
       "os": {
        "iOS": {
         "deprecated": "7.0"
        }
       },
       "subkeys": [
        {
         "name": "MatchDomainAlwaysElement",
         "title": "Match domain always element",
         "type": "string"
        }
       ]
      },
      {
       "name": "OnDemandMatchDomainsNever",
       "title": "On demand match domains never",
       "type": "array",
       "os": {
        "iOS": {
         "deprecated": "7.0"
        }
       },
       "subkeys": [
        {
         "name": "MatchDomainNeverElement",
         "title": "Match domain never element",
         "type": "string"
        }
       ]
      },
      {
       "name": "OnDemandMatchDomainsOnRetry",
       "title": "On demand match domains on retry",
       "type": "array",
       "os": {
        "iOS": {
         "deprecated": "7.0"
        }
       },
       "subkeys": [
        {
         "name": "MatchDomainOnRetryElement",
         "title": "Match domain on retry element",
         "type": "string"
        }
       ]
      },
      {
       "name": "OnDemandRules",
       "title": "On demand rules",
       "type": "array",
       "subkeys": [
        {
         "name": "OnDemandRulesElement",
         "title": "On demand rules element",
         "type": "dictionary",
         "subkeys": [
          {
           "name": "Action",
           "title": "On demand action",
           "type": "string",
           "required": true,
           "rangelist": [
            "Allow",
            "Connect",
            "Disconnect",
            "EvaluateConnection",
            "Ignore"
           ]
          },
          {
           "name": "ActionParameters",
           "title": "Action parameters",
           "type": "array",
           "subkeys": [
            {
             "name": "ActionParameter",
             "title": "Action parameter",
             "type": "dictionary",
             "subkeys": [
              {
               "name": "Domains",
               "title": "Domains",
               "type": "array",
               "required": true,
               "subkeys": [
                {
                 "name": "DomainsElement",
                 "title": "Domains element",
                 "type": "string"
                }
               ]
              },
              {
               "name": "DomainAction",
               "title": "Domain action",
               "type": "string",
               "required": true,
               "rangelist": [
                "ConnectIfNeeded",
                "NeverConnect"
               ]
              },
              {
               "name": "RequiredDNSServers",
               "title": "Required DNS servers",
               "type": "array",
               "subkeys": [
                {
                 "name": "RequiredDNSServersElement",
                 "title": "Required DNS servers element",
                 "type": "string"
                }
               ]
              },
              {
               "name": "RequiredURLStringProbe",
               "title": "Required URL string probe",
               "type": "string"
              }
             ]
            }
           ]
          },
          {
           "name": "DNSDomainMatch",
           "title": "DNS domain match",
           "type": "array",
           "subkeys": [
            {
             "name": "DNSDomainMatchElement",
             "title": "DNS domain match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "DNSServerAddressMatch",
           "title": "DNS server address match",
           "type": "array",
           "subkeys": [
            {
             "name": "DNSServerAddressMatchElement",
             "title": "DNS server address match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "InterfaceTypeMatch",
           "title": "Interface type match",
           "type": "string",
           "rangelist": [
            "Ethernet",
            "WiFi",
            "Cellular"
           ]
          },
          {
           "name": "SSIDMatch",
           "title": "SSID match",
           "type": "array",
           "subkeys": [
            {
             "name": "SSIDMatchElement",
             "title": "SSID match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "URLStringProbe",
           "title": "URL string probe",
           "type": "string"
          }
         ]
        }
       ]
      }
     ]
    },
    {
     "name": "IKEv2",
     "title": "IKEv2",
     "type": "dictionary",
     "os": {
      "watchOS": {
       "introduced": "10.0"
      }
     },
     "subkeys": [
      {
       "name": "RemoteAddress",
       "title": "RemoteAddress",
       "type": "string",
       "required": true
      },
      {
       "name": "LocalIdentifier",
       "title": "LocalIdentifier",
       "type": "string",
       "required": true
      },
      {
       "name": "RemoteIdentifier",
       "title": "RemoteIdentifier",
       "type": "string",
       "required": true
      },
      {
       "name": "AuthenticationMethod",
       "title": "AuthenticationMethod",
       "type": "string",
       "required": true,
       "rangelist": [
        "None",
        "SharedSecret",
        "Certificate"
       ]
      },
      {
       "name": "CertificateType",
       "title": "Certificate type",
       "type": "string",
       "rangelist": [
        "RSA",
        "ECDSA256",
        "ECDSA384",
        "ECDSA521",
        "RSA-PSS"
       ]
      },
      {
       "name": "PayloadCertificateUUID",
       "title": "PayloadCertificateUUID",
       "type": "string"
      },
      {
       "name": "Password",
       "title": "Account password",
       "type": "string"
      },
      {
       "name": "ProviderBundleIdentifier",
       "title": "Provider bundle identifier",
       "type": "string"
      },
      {
       "name": "ProviderDesignatedRequirement",
       "title": "Provider designated requirement",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "n/a"
        },
        "macOS": {
         "introduced": "10.15"
        },
        "visionOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "SharedSecret",
       "title": "SharedSecret",
       "type": "string"
      },
      {
       "name": "ExtendedAuthEnabled",
       "title": "ExtendedAuthEnabled",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "AuthName",
       "title": "AuthName",
       "type": "string"
      },
      {
       "name": "AuthPassword",
       "title": "AuthPassword",
       "type": "string"
      },
      {
       "name": "OnDemandEnabled",
       "title": "Enable VPN on demand",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "OnDemandUserOverrideDisabled",
       "title": "Prevent users from toggling VPN on demand",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "14.0"
        },
        "macOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "OnDemandRules",
       "title": "On demand rules",
       "type": "array",
       "subkeys": [
        {
         "name": "OnDemandRulesElement",
         "title": "On demand rules element",
         "type": "dictionary",
         "subkeys": [
          {
           "name": "Action",
           "title": "On demand action",
           "type": "string",
           "required": true,
           "rangelist": [
            "Allow",
            "Connect",
            "Disconnect",
            "EvaluateConnection",
            "Ignore"
           ]
          },
          {
           "name": "ActionParameters",
           "title": "Action parameters",
           "type": "array",
           "subkeys": [
            {
             "name": "ActionParameter",
             "title": "Action parameter",
             "type": "dictionary",
             "subkeys": [
              {
               "name": "Domains",
               "title": "Domains",
               "type": "array",
               "required": true,
               "subkeys": [
                {
                 "name": "DomainsElement",
                 "title": "Domains element",
                 "type": "string"
                }
               ]
              },
              {
               "name": "DomainAction",
               "title": "Domain action",
               "type": "string",
               "required": true,
               "rangelist": [
                "ConnectIfNeeded",
                "NeverConnect"
               ]
              },
              {
               "name": "RequiredDNSServers",
               "title": "Required DNS servers",
               "type": "array",
               "subkeys": [
                {
                 "name": "RequiredDNSServersElement",
                 "title": "Required DNS servers element",
                 "type": "string"
                }
               ]
              },
              {
               "name": "RequiredURLStringProbe",
               "title": "Required URL string probe",
               "type": "string"
              }
             ]
            }
           ]
          },
          {
           "name": "DNSDomainMatch",
           "title": "DNS domain match",
           "type": "array",
           "subkeys": [
            {
             "name": "DNSDomainMatchElement",
             "title": "DNS domain match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "DNSServerAddressMatch",
           "title": "DNS server address match",
           "type": "array",
           "subkeys": [
            {
             "name": "DNSServerAddressMatchElement",
             "title": "DNS server address match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "InterfaceTypeMatch",
           "title": "Interface type match",
           "type": "string",
           "rangelist": [
            "Ethernet",
            "WiFi",
            "Cellular"
           ]
          },
          {
           "name": "SSIDMatch",
           "title": "SSID match",
           "type": "array",
           "subkeys": [
            {
             "name": "SSIDMatchElement",
             "title": "SSID match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "URLStringProbe",
           "title": "URL string probe",
           "type": "string"
          }
         ]
        }
       ]
      },
      {
       "name": "DeadPeerDetectionRate",
       "title": "Dead peer detection rate",
       "type": "string",
       "os": {
        "watchOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        "None",
        "Low",
        "Medium",
        "High"
       ]
      },
      {
       "name": "ServerCertificateIssuerCommonName",
       "title": "ServerCertificateIssuerCommonName",
       "type": "string"
      },
      {
       "name": "ServerCertificateCommonName",
       "title": "ServerCertificateCommonName",
       "type": "string"
      },
      {
       "name": "TLSMinimumVersion",
       "title": "TLS minimum version",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "11.0"
        },
        "macOS": {
         "introduced": "10.13"
        }
       },
       "rangelist": [
        "1.0",
        "1.1",
        "1.2",
        "1.3"
       ]
      },
      {
       "name": "TLSMaximumVersion",
       "title": "TLS maximum version",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "11.0"
        },
        "macOS": {
         "introduced": "10.13"
        }
       },
       "rangelist": [
        "1.0",
        "1.1",
        "1.2",
        "1.3"
       ]
      },
      {
       "name": "UseConfigurationAttributeInternalIPSubnet",
       "title": "Use IPv4 / IPv6 internal subnet attributes",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "9.0"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "DisableMOBIKE",
       "title": "Disable mobility and multihoming",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "9.0"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "DisableRedirect",
       "title": "Disable redirect",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "9.0"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "DisconnectOnIdle",
       "title": "Enable disconnect on idle",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "DisconnectOnIdleTimer",
       "title": "Disconnect on idle time",
       "type": "integer"
      },
      {
       "name": "NATKeepAliveOffloadEnable",
       "title": "NAT keep alive offload enable",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "9.0"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "NATKeepAliveInterval",
       "title": "NAT keepalive interval",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "9.0"
        }
       }
      },
      {
       "name": "EnablePFS",
       "title": "Enable perfect forward secrecy",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "9.0"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "EnableCertificateRevocationCheck",
       "title": "Enable certificate revocation check",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "9.0"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "EnableFallback",
       "title": "Enable fallback",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "13.0"
        },
        "macOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "MTU",
       "title": "Maximum transmission unit",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "14.0"
        },
        "macOS": {
         "introduced": "11.0"
        }
       },
       "range": {
        "min": 1280,
        "max": 1400
       }
      },
      {
       "name": "ProviderType",
       "type": "string",
       "rangelist": [
        "packet-tunnel",
        "app-proxy"
       ]
      },
      {
       "name": "IncludeAllNetworks",
       "title": "Include all networks",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "14.0"
        },
        "macOS": {
         "introduced": "10.15"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "EnforceRoutes",
       "title": "Enforce routes",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "14.2"
        },
        "macOS": {
         "introduced": "11.0"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "ExcludeLocalNetworks",
       "title": "Exclude local networks",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "14.2"
        },
        "macOS": {
         "introduced": "10.15"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "ExcludeCellularServices",
       "title": "Exclude cellular services",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "16.4"
        },
        "macOS": {
         "introduced": "13.3"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "ExcludeAPNs",
       "title": "Exclude APNs",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "16.4"
        },
        "macOS": {
         "introduced": "13.3"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "ExcludeDeviceCommunication",
       "title": "Exclude device communication",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "17.4"
        },
        "macOS": {
         "introduced": "14.4"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "1.1"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "PPK",
       "title": "Post-quantum pre-shared key",
       "type": "data",
       "os": {
        "iOS": {
         "introduced": "18.0"
        },
        "macOS": {
         "introduced": "15.0"
        },
        "tvOS": {
         "introduced": "18.0"
        },
        "visionOS": {
         "introduced": "2.0"
        },
        "watchOS": {
         "introduced": "11.0"
        }
       }
      },
      {
       "name": "PPKIdentifier",
       "title": "Post-quantum pre-shared key identifier",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "18.0"
        },
        "macOS": {
         "introduced": "15.0"
        },
        "tvOS": {
         "introduced": "18.0"
        },
        "visionOS": {
         "introduced": "2.0"
        },
        "watchOS": {
         "introduced": "11.0"
        }
       }
      },
      {
       "name": "PPKMandatory",
       "title": "Post-quantum pre-shared key mandatory",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "18.0"
        },
        "macOS": {
         "introduced": "15.0"
        },
        "tvOS": {
         "introduced": "18.0"
        },
        "visionOS": {
         "introduced": "2.0"
        },
        "watchOS": {
         "introduced": "11.0"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "AllowPostQuantumKeyExchangeFallback",
       "title": "Allow post-quantum key exchange fallback",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "26.0"
        },
        "macOS": {
         "introduced": "26.0"
        },
        "tvOS": {
         "introduced": "26.0"
        },
        "visionOS": {
         "introduced": "26.0"
        },
        "watchOS": {
         "introduced": "26.0"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "EnforceStrictAlgorithmSelection",
       "title": "Enforce strict algorithm selection",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "18.5"
        },
        "macOS": {
         "introduced": "15.5"
        },
        "tvOS": {
         "introduced": "18.5"
        },
        "visionOS": {
         "introduced": "2.5"
        },
        "watchOS": {
         "introduced": "11.5"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "IKESecurityAssociationParameters",
       "title": "IKESecurityAssociationParameters",
       "type": "dictionary",
       "subkeys": [
        {
         "name": "EncryptionAlgorithm",
         "title": "EncryptionAlgorithm",
         "type": "string",
         "rangelist": [
          "DES",
          "3DES",
          "AES-128",
          "AES-256",
          "AES-128-GCM",
          "AES-256-GCM",
          "ChaCha20Poly1305"
         ]
        },
        {
         "name": "IntegrityAlgorithm",
         "title": "IntegrityAlgorithm",
         "type": "string",
         "rangelist": [
          "SHA1-96",
          "SHA1-160",
          "SHA2-256",
          "SHA2-384",
          "SHA2-512"
         ]
        },
        {
         "name": "DiffieHellmanGroup",
         "title": "DiffieHellmanGroup",
         "type": "integer",
         "rangelist": [
          1,
          2,
          5,
          14,
          15,
          16,
          17,
          18,
          19,
          20,
          21,
          31,
          32
         ]
        },
        {
         "name": "PostQuantumKeyExchangeMethods",
         "title": "Post-quantum key exchange methods",
         "type": "array",
         "os": {
          "iOS": {
           "introduced": "26.0"
          },
          "macOS": {
           "introduced": "26.0"
          },
          "tvOS": {
           "introduced": "16.0"
          },
          "visionOS": {
           "introduced": "26.0"
          },
          "watchOS": {
           "introduced": "26.0"
          }
         },
         "subkeys": [
          {
           "name": "PostQuantumKeyExchangeMethod",
           "title": "Post-quantum key exchange method",
           "type": "integer",
           "rangelist": [
            0,
            36,
            37
           ]
          }
         ]
        },
        {
         "name": "LifeTimeInMinutes",
         "title": "LifeTimeInMinutes",
         "type": "integer",
         "range": {
          "min": 10,
          "max": 1440
         }
        }
       ]
      },
      {
       "name": "ChildSecurityAssociationParameters",
       "title": "ChildSecurityAssociationParameters",
       "type": "dictionary",
       "subkeys": [
        {
         "name": "EncryptionAlgorithm",
         "title": "EncryptionAlgorithm",
         "type": "string",
         "rangelist": [
          "DES",
          "3DES",
          "AES-128",
          "AES-256",
          "AES-128-GCM",
          "AES-256-GCM",
          "ChaCha20Poly1305"
         ]
        },
        {
         "name": "IntegrityAlgorithm",
         "title": "IntegrityAlgorithm",
         "type": "string",
         "rangelist": [
          "SHA1-96",
          "SHA1-160",
          "SHA2-256",
          "SHA2-384",
          "SHA2-512"
         ]
        },
        {
         "name": "DiffieHellmanGroup",
         "title": "DiffieHellmanGroup",
         "type": "integer",
         "rangelist": [
          1,
          2,
          5,
          14,
          15,
          16,
          17,
          18,
          19,
          20,
          21,
          31,
          32
         ]
        },
        {
         "name": "PostQuantumKeyExchangeMethods",
         "title": "Post-quantum key exchange methods",
         "type": "array",
         "os": {
          "iOS": {
           "introduced": "26.0"
          },
          "macOS": {
           "introduced": "26.0"
          },
          "tvOS": {
           "introduced": "16.0"
          },
          "visionOS": {
           "introduced": "26.0"
          },
          "watchOS": {
           "introduced": "26.0"
          }
         },
         "subkeys": [
          {
           "name": "PostQuantumKeyExchangeMethod",
           "title": "Post-quantum key exchange method",
           "type": "integer",
           "rangelist": [
            0,
            36,
            37
           ]
          }
         ]
        },
        {
         "name": "LifeTimeInMinutes",
         "title": "LifeTimeInMinutes",
         "type": "integer",
         "range": {
          "min": 10,
          "max": 1440
         }
        }
       ]
      }
     ]
    },
    {
     "name": "DNS",
     "title": "DNS",
     "type": "dictionary",
     "os": {
      "watchOS": {
       "introduced": "10.0"
      }
     },
     "subkeys": [
      {
       "name": "DNSProtocol",
       "title": "DNS protocol",
       "type": "string",
       "required": true,
       "os": {
        "iOS": {
         "introduced": "14.0"
        },
        "macOS": {
         "introduced": "11.0"
        }
       },
       "rangelist": [
        "Cleartext",
        "HTTPS",
        "TLS"
       ]
      },
      {
       "name": "ServerURL",
       "title": "Server URL",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "14.0"
        },
        "macOS": {
         "introduced": "11.0"
        }
       }
      },
      {
       "name": "ServerName",
       "title": "Server name",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "14.0"
        },
        "macOS": {
         "introduced": "11.0"
        }
       }
      },
      {
       "name": "ServerAddresses",
       "title": "DNS server addresses",
       "type": "array",
       "required": true,
       "os": {
        "iOS": {
         "introduced": "10.0"
        },
        "macOS": {
         "introduced": "10.12"
        }
       },
       "subkeys": [
        {
         "name": "ServerAddressesElement",
         "title": "Server address element",
         "type": "string"
        }
       ]
      },
      {
       "name": "SearchDomains",
       "title": "DNS search domains",
       "type": "array",
       "os": {
        "iOS": {
         "introduced": "10.0"
        },
        "macOS": {
         "introduced": "10.12"
        }
       },
       "subkeys": [
        {
         "name": "SearchDomainsElement",
         "title": "Search domains element",
         "type": "string"
        }
       ]
      },
      {
       "name": "DomainName",
       "title": "Domain name",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "10.0"
        },
        "macOS": {
         "introduced": "10.12"
        }
       }
      },
      {
       "name": "SupplementalMatchDomains",
       "title": "Supplemental match domains",
       "type": "array",
       "os": {
        "iOS": {
         "introduced": "10.0"
        },
        "macOS": {
         "introduced": "10.12"
        }
       },
       "subkeys": [
        {
         "name": "SupplementalMatchDomainsElement",
         "title": "Supplemental match domains element",
         "type": "string"
        }
       ]
      },
      {
       "name": "SupplementalMatchDomainsNoSearch",
       "title": "Supplemental match domains no search",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "10.0"
        },
        "macOS": {
         "introduced": "10.12"
        }
       },
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "PayloadCertificateUUID",
       "title": "DNS certificate UUID",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "16.0"
        },
        "macOS": {
         "introduced": "13.0"
        }
       },
       "format": "^[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}$"
      }
     ]
    },
    {
     "name": "Proxies",
     "title": "Proxies",
     "type": "dictionary",
     "os": {
      "watchOS": {
       "introduced": "10.0"
      }
     },
     "subkeys": [
      {
       "name": "ProxyAutoConfigEnable",
       "title": "Proxy AutoConfig enable",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "ProxyAutoDiscoveryEnable",
       "title": "Proxy auto discovery enable",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "ProxyAutoConfigURLString",
       "title": "Proxy server URL",
       "type": "string"
      },
      {
       "name": "SupplementalMatchDomains",
       "title": "Supplemental match domains",
       "type": "array",
       "subkeys": [
        {
         "name": "SupplementalMatchDomainsElement",
         "title": "Supplemental match domains element",
         "type": "string"
        }
       ]
      },
      {
       "name": "HTTPEnable",
       "title": "Enable HTTP",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "HTTPProxy",
       "title": "HTTP proxy",
       "type": "string"
      },
      {
       "name": "HTTPPort",
       "title": "HTTP port",
       "type": "integer",
       "range": {
        "min": 0,
        "max": 65535
       }
      },
      {
       "name": "HTTPProxyUsername",
       "title": "HTTP ProxyUsername",
       "type": "string"
      },
      {
       "name": "HTTPProxyPassword",
       "title": "HTTP ProxyPassword",
       "type": "string"
      },
      {
       "name": "HTTPSEnable",
       "title": "Enable HTTPS",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "HTTPSProxy",
       "title": "HTTPS proxy",
       "type": "string"
      },
      {
       "name": "HTTPSPort",
       "title": "HTTPS port",
       "type": "integer",
       "range": {
        "min": 0,
        "max": 65535
       }
      }
     ]
    },
    {
     "name": "AlwaysOn",
     "title": "AlwaysOn",
     "type": "dictionary",
     "os": {
      "iOS": {
       "introduced": "8.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "UIToggleEnabled",
       "title": "UI toggle enabled",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "TunnelConfigurations",
       "title": "TunnelConfigurations",
       "type": "array",
       "required": true,
       "subkeys": [
        {
         "name": "TunnelConfigurationElement",
         "title": "A TunnelConfiguration element",
         "type": "dictionary",
         "subkeys": [
          {
           "name": "ProtocolType",
           "title": "Protocol type",
           "type": "string",
           "required": true,
           "rangelist": [
            "IKEv2"
           ]
          },
          {
           "name": "Interfaces",
           "title": "Interfaces",
           "type": "array",
           "subkeys": [
            {
             "name": "InterfacesElement",
             "title": "Interfaces element",
             "type": "string",
             "rangelist": [
              "Cellular",
              "WiFi"
             ]
            }
           ]
          }
         ]
        }
       ]
      },
      {
       "name": "ServiceExceptions",
       "title": "ServiceExceptions",
       "type": "array",
       "subkeys": [
        {
         "name": "ServiceExceptionElement",
         "title": "A ServiceException element",
         "type": "dictionary",
         "subkeys": [
          {
           "name": "ServiceName",
           "title": "Service name",
           "type": "string",
           "required": true,
           "rangelist": [
            "VoiceMail",
            "AirPrint",
            "CellularServices",
            "DeviceCommunication"
           ]
          },
          {
           "name": "Action",
           "title": "Action",
           "type": "string",
           "required": true,
           "rangelist": [
            "Allow",
            "Drop"
           ]
          }
         ]
        }
       ]
      },
      {
       "name": "ApplicationExceptions",
       "title": "ApplicationExceptions",
       "type": "array",
       "os": {
        "iOS": {
         "introduced": "13.6"
        }
       },
       "subkeys": [
        {
         "name": "ApplicationExceptionElement",
         "title": "A ApplicationException element",
         "type": "dictionary",
         "subkeys": [
          {
           "name": "BundleIdentifier",
           "title": "Bundle identifier",
           "type": "string",
           "required": true
          },
          {
           "name": "LimitToProtocols",
           "title": "LimitToProtocols",
           "type": "array",
           "subkeys": [
            {
             "name": "LimitToProtocolElement",
             "title": "LimitToProtocol element",
             "type": "string",
             "rangelist": [
              "UDP"
             ]
            }
           ]
          }
         ]
        }
       ]
      },
      {
       "name": "AllowCaptiveWebSheet",
       "title": "Allow captive web sheet",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "AllowAllCaptiveNetworkPlugins",
       "title": "Allow all captive network plugins",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "AllowedCaptiveNetworkPlugins",
       "title": "AllowedCaptiveNetworkPlugins",
       "type": "array",
       "subkeys": [
        {
         "name": "AllowedCaptiveNetworkPluginElement",
         "title": "An AllowedCaptiveNetworkPlugin element",
         "type": "dictionary",
         "subkeys": [
          {
           "name": "BundleIdentifier",
           "title": "Bundle identifier",
           "type": "string",
           "required": true
          }
         ]
        }
       ]
      }
     ]
    },
    {
     "name": "TransparentProxy",
     "title": "TransparentProxy",
     "type": "dictionary",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "14.0"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "AuthenticationMethod",
       "title": "Authentication method",
       "type": "string",
       "rangelist": [
        "Password",
        "Certificate",
        "Password+Certificate"
       ]
      },
      {
       "name": "DisconnectOnIdle",
       "title": "Enable disconnect on idle",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "DisconnectOnIdleTimer",
       "title": "Disconnect on idle time",
       "type": "integer"
      },
      {
       "name": "EnforceRoutes",
       "title": "Enforce routes",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "OnDemandEnabled",
       "title": "Enable VPN on demand",
       "type": "integer",
       "rangelist": [
        0,
        1
       ]
      },
      {
       "name": "OnDemandRules",
       "title": "On demand rules",
       "type": "array",
       "subkeys": [
        {
         "name": "OnDemandRulesElement",
         "title": "On demand rules element",
         "type": "dictionary",
         "subkeys": [
          {
           "name": "Action",
           "title": "On demand action",
           "type": "string",
           "required": true,
           "rangelist": [
            "Allow",
            "Connect",
            "Disconnect",
            "EvaluateConnection",
            "Ignore"
           ]
          },
          {
           "name": "ActionParameters",
           "title": "Action parameters",
           "type": "array",
           "subkeys": [
            {
             "name": "ActionParameter",
             "title": "Action parameter",
             "type": "dictionary",
             "subkeys": [
              {
               "name": "Domains",
               "title": "Domains",
               "type": "array",
               "required": true,
               "subkeys": [
                {
                 "name": "DomainsElement",
                 "title": "Domains element",
                 "type": "string"
                }
               ]
              },
              {
               "name": "DomainAction",
               "title": "Domain action",
               "type": "string",
               "required": true,
               "rangelist": [
                "ConnectIfNeeded",
                "NeverConnect"
               ]
              },
              {
               "name": "RequiredDNSServers",
               "title": "Required DNS servers",
               "type": "array",
               "subkeys": [
                {
                 "name": "RequiredDNSServersElement",
                 "title": "Required DNS servers element",
                 "type": "string"
                }
               ]
              },
              {
               "name": "RequiredURLStringProbe",
               "title": "Required URL string probe",
               "type": "string"
              }
             ]
            }
           ]
          },
          {
           "name": "DNSDomainMatch",
           "title": "DNS domain match",
           "type": "array",
           "subkeys": [
            {
             "name": "DNSDomainMatchElement",
             "title": "DNS domain match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "DNSServerAddressMatch",
           "title": "DNS server address match",
           "type": "array",
           "subkeys": [
            {
             "name": "DNSServerAddressMatchElement",
             "title": "DNS server address match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "InterfaceTypeMatch",
           "title": "Interface type match",
           "type": "string",
           "rangelist": [
            "Ethernet",
            "WiFi",
            "Cellular"
           ]
          },
          {
           "name": "SSIDMatch",
           "title": "SSID match",
           "type": "array",
           "subkeys": [
            {
             "name": "SSIDMatchElement",
             "title": "SSID match element",
             "type": "string"
            }
           ]
          },
          {
           "name": "URLStringProbe",
           "title": "URL string probe",
           "type": "string"
          }
         ]
        }
       ]
      },
      {
       "name": "PayloadCertificateUUID",
       "title": "PayloadCertificateUUID",
       "type": "string"
      },
      {
       "name": "Password",
       "title": "Account password",
       "type": "string"
      },
      {
       "name": "ProviderBundleIdentifier",
       "title": "Provider bundle identifier",
       "type": "string"
      },
      {
       "name": "ProviderDesignatedRequirement",
       "title": "Provider designated requirement",
       "type": "string"
      },
      {
       "name": "ProviderType",
       "type": "string",
       "rangelist": [
        "packet-tunnel",
        "app-proxy"
       ]
      },
      {
       "name": "Order",
       "title": "Order",
       "type": "integer"
      }
     ]
    }
   ]
  },
  "com.apple.webcontent-filter": {
   "type": "com.apple.webcontent-filter",
   "family": "profile_payload",
   "title": "Web Content Filter",
   "os": {
    "iOS": {
     "introduced": "7.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "10.15",
     "userEnrollment": "forbidden"
    },
    "tvOS": {
     "introduced": "n/a"
    },
    "visionOS": {
     "introduced": "1.1",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a"
    }
   },
   "multiple": true,
   "keys": [
    {
     "name": "FilterType",
     "title": "FilterType",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "8.0"
      }
     },
     "rangelist": [
      "BuiltIn",
      "Plugin"
     ]
    },
    {
     "name": "SafariHistoryRetentionEnabled",
     "title": "SafariHistoryRetentionEnabled",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "26.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "26.0"
      },
      "visionOS": {
       "introduced": "26.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      }
     }
    },
    {
     "name": "AutoFilterEnabled",
     "title": "Web filter enabled",
     "type": "boolean",
     "os": {
      "macOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "PermittedURLs",
     "title": "PermittedURLs",
     "type": "array",
     "os": {
      "macOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "PermittedURLItems",
       "title": "Permitted url items",
       "type": "string"
      }
     ]
    },
    {
     "name": "BlacklistedURLs",
     "title": "BlacklistedURLs",
     "type": "array",
     "os": {
      "iOS": {
       "deprecated": "14.5"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "BlacklistedURLItems",
       "title": "Blacklisted url items",
       "type": "string"
      }
     ]
    },
    {
     "name": "DenyListURLs",
     "title": "DenyListURLs",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "14.5"
      },
      "macOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "DenyListURLItems",
       "title": "Denylisted url items",
       "type": "string"
      }
     ]
    },
    {
     "name": "HideDenyListURLs",
     "title": "HideDenyListURLs",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "18.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "2.0"
      }
     }
    },
    {
     "name": "WhitelistedBookmarks",
     "title": "White list",
     "type": "array",
     "os": {
      "iOS": {
       "deprecated": "14.5"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "WhitelistedBookmarksItem",
       "title": "Identifier",
       "type": "dictionary",
       "subkeys": [
        {
         "name": "URL",
         "title": "URL",
         "type": "string",
         "required": true
        },
        {
         "name": "Title",
         "title": "Title",
         "type": "string",
         "required": true
        }
       ]
      }
     ]
    },
    {
     "name": "AllowListBookmarks",
     "title": "Allow list",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "14.5"
      },
      "macOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "AllowListBookmarksItem",
       "title": "Identifier",
       "type": "dictionary",
       "subkeys": [
        {
         "name": "URL",
         "title": "URL",
         "type": "string",
         "required": true
        },
        {
         "name": "Title",
         "title": "Title",
         "type": "string",
         "required": true
        }
       ]
      }
     ]
    },
    {
     "name": "UserDefinedName",
     "title": "UserDefinedName",
     "type": "string"
    },
    {
     "name": "PluginBundleID",
     "title": "PluginBundleID",
     "type": "string"
    },
    {
     "name": "ServerAddress",
     "title": "ServerAddress",
     "type": "string"
    },
    {
     "name": "UserName",
     "title": "Username",
     "type": "string"
    },
    {
     "name": "Password",
     "title": "Password",
     "type": "string"
    },
    {
     "name": "PayloadCertificateUUID",
     "title": "Certificate UUID",
     "type": "string",
     "format": "^[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}$"
    },
    {
     "name": "Organization",
     "title": "Organization",
     "type": "string"
    },
    {
     "name": "VendorConfig",
     "type": "dictionary",
     "subkeys": [
      {
       "name": "ANY",
       "type": "any",
       "required": true
      }
     ]
    },
    {
     "name": "FilterBrowsers",
     "title": "FilterBrowsers",
     "type": "boolean",
     "os": {
      "macOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "FilterSockets",
     "title": "FilterSockets",
     "type": "boolean"
    },
    {
     "name": "FilterDataProviderDesignatedRequirement",
     "title": "Filter data provider designated requirement",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "FilterDataProviderBundleIdentifier",
     "title": "Filter data provider bundle identifier",
     "type": "string"
    },
    {
     "name": "FilterPackets",
     "title": "Filter network packets",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.15"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "FilterPacketProviderDesignatedRequirement",
     "title": "Filter packet provider designated requirement",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.15"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "FilterPacketProviderBundleIdentifier",
     "title": "Filter packet provider bundle identifier",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.15"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "FilterGrade",
     "title": "Filter grade",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.15"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     },
     "rangelist": [
      "firewall",
      "inspector"
     ]
    },
    {
     "name": "ContentFilterUUID",
     "title": "Content filter UUID",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "16.0"
      },
      "macOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "FilterURLs",
     "title": "FilterURLs",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "26.0"
      },
      "macOS": {
       "introduced": "26.0"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "URLFilterParameters",
     "type": "dictionary",
     "os": {
      "iOS": {
       "introduced": "26.0"
      },
      "macOS": {
       "introduced": "26.0"
      },
      "visionOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "URLFilterControlProviderDesignatedRequirement",
       "title": "URL filter control provider designated requirement",
       "type": "string"
      },
      {
       "name": "URLFilterControlProviderBundleIdentifier",
       "title": "URL filter control provider bundle identifier",
       "type": "string",
       "required": true
      },
      {
       "name": "PIRServerURL",
       "title": "Private information retrieval server URL",
       "type": "string",
       "required": true
      },
      {
       "name": "PIRPrivacyPassIssuerURL",
       "title": "Privacy pass issuer URL",
       "type": "string",
       "required": true
      },
      {
       "name": "PIRAuthenticationToken",
       "title": "Authentication token",
       "type": "string",
       "required": true
      },
      {
       "name": "URLFilterFailClosed",
       "title": "URLFilterFailClosed",
       "type": "boolean"
      },
      {
       "name": "URLPrefilterFetchFrequency",
       "title": "URLPrefilterFetchFrequency",
       "type": "integer",
       "range": {
        "min": 2700
       }
      }
     ]
    }
   ]
  },
  "com.apple.wifi.managed": {
   "type": "com.apple.wifi.managed",
   "family": "profile_payload",
   "title": "Wi-Fi",
   "os": {
    "iOS": {
     "introduced": "4.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "10.7",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "9.0",
     "supervised": false
    },
    "visionOS": {
     "introduced": "1.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "3.2"
    }
   },
   "multiple": true,
   "keys": [
    {
     "name": "AutoJoin",
     "title": "Auto join",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "5.0"
      }
     }
    },
    {
     "name": "SSID_STR",
     "title": "SSID",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "7.0"
      }
     }
    },
    {
     "name": "HIDDEN_NETWORK",
     "title": "Hidden",
     "type": "boolean"
    },
    {
     "name": "ProxyType",
     "title": "Proxy type",
     "type": "string",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "visionOS": {
       "userEnrollment": "forbidden"
      }
     },
     "rangelist": [
      "None",
      "Manual",
      "Auto"
     ]
    },
    {
     "name": "EncryptionType",
     "title": "Encryption type",
     "type": "string",
     "rangelist": [
      "WEP",
      "WPA",
      "WPA2",
      "WPA3",
      "Any",
      "None"
     ]
    },
    {
     "name": "Password",
     "title": "Password",
     "type": "string"
    },
    {
     "name": "PayloadCertificateUUID",
     "title": "Certificate UUID",
     "type": "string",
     "format": "^[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}$"
    },
    {
     "name": "EAPClientConfiguration",
     "title": "EAP client configuration",
     "type": "dictionary",
     "subkeys": [
      {
       "name": "AcceptEAPTypes",
       "title": "Accept EAP types",
       "type": "array",
       "required": true,
       "subkeys": [
        {
         "name": "EAPType",
         "title": "EAP type",
         "type": "integer",
         "rangelist": [
          13,
          17,
          18,
          21,
          23,
          25,
          43
         ]
        }
       ]
      },
      {
       "name": "UserName",
       "title": "Username",
       "type": "string"
      },
      {
       "name": "UserPassword",
       "title": "Password",
       "type": "string"
      },
      {
       "name": "PayloadCertificateAnchorUUID",
       "title": "Certificate anchor UUID",
       "type": "array",
       "subkeys": [
        {
         "name": "CertificateAnchorUUID",
         "title": "Individual certificate anchor UUID",
         "type": "string",
         "format": "^[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}$"
        }
       ]
      },
      {
       "name": "TLSTrustedCertificates",
       "title": "TLS trusted certificates",
       "type": "array",
       "subkeys": [
        {
         "name": "TLSTrustedCertificatesItem",
         "type": "string",
         "required": true
        }
       ]
      },
      {
       "name": "TLSTrustedServerNames",
       "title": "TLS trusted server names",
       "type": "array",
       "subkeys": [
        {
         "name": "TLSTrustedServerName",
         "title": "Individual trusted TLS server name",
         "type": "string"
        }
       ]
      },
      {
       "name": "TLSAllowTrustExceptions",
       "title": "Allow trust exceptions",
       "type": "boolean",
       "os": {
        "iOS": {
         "removed": "8.0"
        },
        "visionOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "TLSCertificateIsRequired",
       "type": "boolean",
       "os": {
        "iOS": {
         "introduced": "7.0"
        }
       }
      },
      {
       "name": "TTLSInnerAuthentication",
       "title": "TTLS inner authentication",
       "type": "string",
       "rangelist": [
        "PAP",
        "EAP",
        "CHAP",
        "MSCHAP",
        "MSCHAPv2"
       ]
      },
      {
       "name": "TLSMinimumVersion",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "11.0"
        },
        "macOS": {
         "introduced": "10.13"
        },
        "tvOS": {
         "introduced": "11.0"
        }
       },
       "rangelist": [
        "1.0",
        "1.1",
        "1.2",
        "1.3"
       ]
      },
      {
       "name": "TLSMaximumVersion",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "11.0"
        },
        "macOS": {
         "introduced": "10.13"
        },
        "tvOS": {
         "introduced": "11.0"
        }
       },
       "rangelist": [
        "1.0",
        "1.1",
        "1.2",
        "1.3"
       ]
      },
      {
       "name": "OuterIdentity",
       "title": "Outer identity",
       "type": "string"
      },
      {
       "name": "EAPFASTUsePAC",
       "title": "Use PAC",
       "type": "boolean"
      },
      {
       "name": "EAPFASTProvisionPAC",
       "title": "Provision PAC",
       "type": "boolean"
      },
      {
       "name": "EAPFASTProvisionPACAnonymously",
       "title": "Provision PAC anonymously",
       "type": "boolean"
      },
      {
       "name": "EAPSIMNumberOfRANDs",
       "title": "Allow two RANDs",
       "type": "integer",
       "os": {
        "iOS": {
         "introduced": "8.0"
        }
       },
       "rangelist": [
        2,
        3
       ]
      },
      {
       "name": "SystemModeCredentialsSource",
       "type": "string"
      },
      {
       "name": "SystemModeUseOpenDirectoryCredentials",
       "type": "boolean"
      },
      {
       "name": "OneTimeUserPassword",
       "title": "Per-connection password",
       "type": "boolean",
       "os": {
        "iOS": {
         "introduced": "8.0"
        },
        "macOS": {
         "introduced": "10.8"
        },
        "tvOS": {
         "introduced": "9.0"
        }
       }
      }
     ]
    },
    {
     "name": "DisplayedOperatorName",
     "title": "Displayed operator name",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "10.9"
      }
     }
    },
    {
     "name": "DomainName",
     "title": "Domain name",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "10.9"
      }
     }
    },
    {
     "name": "RoamingConsortiumOIs",
     "title": "Roaming OIs",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "10.9"
      }
     },
     "subkeys": [
      {
       "name": "RoamingConsortiumOI",
       "type": "string",
       "format": "^([0-9A-Za-z]{6})|([0-9A-Za-z]{9})$"
      }
     ]
    },
    {
     "name": "ServiceProviderRoamingEnabled",
     "title": "Roaming enable",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "10.9"
      }
     }
    },
    {
     "name": "IsHotspot",
     "title": "Is hotspot",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "10.9"
      }
     }
    },
    {
     "name": "HESSID",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "7.0"
      }
     }
    },
    {
     "name": "NAIRealmNames",
     "title": "Realm names",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "10.9"
      }
     },
     "subkeys": [
      {
       "name": "NAIRealmName",
       "type": "string"
      }
     ]
    },
    {
     "name": "MCCAndMNCs",
     "title": "MCC/MNCs",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "7.0"
      },
      "macOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "MCCAndMNC",
       "type": "string",
       "format": "^[0-9]{6}$"
      }
     ]
    },
    {
     "name": "CaptiveBypass",
     "title": "Disable captive network detection",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "10.0"
      },
      "macOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "QoSMarkingPolicy",
     "title": "QoS marking policy",
     "type": "dictionary",
     "os": {
      "iOS": {
       "introduced": "10.0"
      },
      "macOS": {
       "introduced": "10.13"
      }
     },
     "subkeys": [
      {
       "name": "QoSMarkingAllowListAppIdentifiers",
       "title": "Allowlisted app identifiers",
       "type": "array",
       "os": {
        "iOS": {
         "introduced": "14.5"
        },
        "macOS": {
         "introduced": "14.0"
        }
       },
       "subkeys": [
        {
         "name": "appBundleID",
         "title": "Allowlisted app",
         "type": "string"
        }
       ]
      },
      {
       "name": "QoSMarkingWhitelistedAppIdentifiers",
       "title": "Whitelisted app identifiers",
       "type": "array",
       "os": {
        "iOS": {
         "deprecated": "14.5"
        },
        "macOS": {
         "deprecated": "14.0"
        },
        "visionOS": {
         "introduced": "n/a"
        }
       },
       "subkeys": [
        {
         "name": "appBundleID",
         "title": "Allowlisted app",
         "type": "string"
        }
       ]
      },
      {
       "name": "QoSMarkingAppleAudioVideoCalls",
       "title": "QoS marking for audio or video calls",
       "type": "boolean"
      },
      {
       "name": "QoSMarkingEnabled",
       "title": "Allow QoS marking",
       "type": "boolean"
      }
     ]
    },
    {
     "name": "SetupModes",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "10.7"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     },
     "subkeys": [
      {
       "name": "SetupModesItem",
       "type": "string",
       "required": true,
       "rangelist": [
        "System",
        "Loginwindow"
       ]
      }
     ]
    },
    {
     "name": "EnableIPv6",
     "type": "boolean"
    },
    {
     "name": "TLSCertificateRequired",
     "title": "Certificate required",
     "type": "boolean"
    },
    {
     "name": "ProxyServer",
     "title": "Proxy server",
     "type": "string",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "userEnrollment": "forbidden"
      },
      "visionOS": {
       "userEnrollment": "forbidden"
      }
     }
    },
    {
     "name": "ProxyServerPort",
     "title": "Proxy server port",
     "type": "integer",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "userEnrollment": "forbidden"
      },
      "visionOS": {
       "userEnrollment": "forbidden"
      }
     },
     "range": {
      "min": 0,
      "max": 65535
     }
    },
    {
     "name": "ProxyUsername",
     "title": "Proxy username",
     "type": "string",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "userEnrollment": "forbidden"
      },
      "visionOS": {
       "userEnrollment": "forbidden"
      }
     }
    },
    {
     "name": "ProxyPassword",
     "title": "Proxy password",
     "type": "string",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "visionOS": {
       "userEnrollment": "forbidden"
      }
     }
    },
    {
     "name": "ProxyPACURL",
     "title": "Proxy PAC URL",
     "type": "string",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "userEnrollment": "forbidden"
      },
      "visionOS": {
       "userEnrollment": "forbidden"
      }
     }
    },
    {
     "name": "ProxyPACFallbackAllowed",
     "title": "Proxy PAC fallback allowed",
     "type": "boolean",
     "os": {
      "iOS": {
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "userEnrollment": "forbidden"
      },
      "visionOS": {
       "userEnrollment": "forbidden"
      }
     }
    },
    {
     "name": "DisableAssociationMACRandomization",
     "title": "Disable MAC address randomization during association",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "14.0",
       "userEnrollment": "forbidden"
      },
      "macOS": {
       "introduced": "15.0",
       "userEnrollment": "forbidden"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "7.0"
      }
     }
    },
    {
     "name": "AllowJoinBeforeFirstUnlock",
     "title": "Allow join before first unlock",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "26.0",
       "supervised": true,
       "userEnrollment": "forbidden"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    }
   ]
  },
  "setting.AccessibilitySettings": {
   "type": "setting.AccessibilitySettings",
   "family": "command",
   "title": "AccessibilitySettings",
   "os": {
    "iOS": {
     "introduced": "16.0",
     "supervised": true,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "10.0",
     "supervised": true
    }
   },
   "keys": [
    {
     "name": "BoldTextEnabled",
     "type": "boolean"
    },
    {
     "name": "IncreaseContrastEnabled",
     "type": "boolean",
     "os": {
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "ReduceMotionEnabled",
     "type": "boolean"
    },
    {
     "name": "ReduceTransparencyEnabled",
     "type": "boolean"
    },
    {
     "name": "TextSize",
     "type": "integer",
     "rangelist": [
      0,
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11
     ]
    },
    {
     "name": "TouchAccommodationsEnabled",
     "type": "boolean"
    },
    {
     "name": "VoiceOverEnabled",
     "type": "boolean"
    },
    {
     "name": "ZoomEnabled",
     "type": "boolean"
    },
    {
     "name": "GrayscaleEnabled",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    }
   ]
  },
  "setting.AppAnalytics": {
   "type": "setting.AppAnalytics",
   "family": "command",
   "title": "AppAnalytics",
   "os": {
    "iOS": {
     "introduced": "9.3.2",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "Enabled",
     "type": "boolean",
     "required": true
    }
   ]
  },
  "setting.ApplicationAttributes": {
   "type": "setting.ApplicationAttributes",
   "family": "command",
   "title": "ApplicationAttributes",
   "os": {
    "iOS": {
     "introduced": "7.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "10.2",
     "supervised": false
    },
    "visionOS": {
     "introduced": "1.1",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "10.0",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "Identifier",
     "type": "string",
     "required": true
    },
    {
     "name": "Attributes",
     "type": "dictionary",
     "subkeys": [
      {
       "name": "VPNUUID",
       "type": "string",
       "os": {
        "tvOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "ContentFilterUUID",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "16.0"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "DNSProxyUUID",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "16.0"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "RelayUUID",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "17.0"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "AssociatedDomains",
       "type": "array",
       "os": {
        "iOS": {
         "introduced": "13.0"
        },
        "tvOS": {
         "introduced": "n/a"
        }
       },
       "subkeys": [
        {
         "name": "AssociatedDomain",
         "type": "string"
        }
       ]
      },
      {
       "name": "AssociatedDomainsEnableDirectDownloads",
       "type": "boolean",
       "os": {
        "iOS": {
         "introduced": "14.0"
        },
        "tvOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "Removable",
       "type": "boolean",
       "os": {
        "iOS": {
         "introduced": "14.0"
        },
        "tvOS": {
         "introduced": "14.0"
        }
       }
      },
      {
       "name": "TapToPayScreenLock",
       "type": "boolean",
       "os": {
        "iOS": {
         "introduced": "16.4"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "CellularSliceUUID",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "17.0"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "Hideable",
       "type": "boolean",
       "os": {
        "iOS": {
         "introduced": "18.1"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "Lockable",
       "type": "boolean",
       "os": {
        "iOS": {
         "introduced": "18.1"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       }
      }
     ]
    }
   ]
  },
  "setting.ApplicationConfiguration": {
   "type": "setting.ApplicationConfiguration",
   "family": "command",
   "title": "ApplicationConfiguration",
   "os": {
    "iOS": {
     "introduced": "7.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "10.15",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "10.2",
     "supervised": false
    },
    "visionOS": {
     "introduced": "1.1",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "10.0",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "Identifier",
     "type": "string",
     "required": true
    },
    {
     "name": "Configuration",
     "type": "dictionary",
     "subkeys": [
      {
       "name": "ANY",
       "type": "any"
      }
     ]
    }
   ]
  },
  "setting.Bluetooth": {
   "type": "setting.Bluetooth",
   "family": "command",
   "title": "Bluetooth",
   "os": {
    "iOS": {
     "introduced": "11.3",
     "supervised": true,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "10.13.4",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "Enabled",
     "type": "boolean",
     "required": true
    }
   ]
  },
  "setting.DataRoaming": {
   "type": "setting.DataRoaming",
   "family": "command",
   "title": "DataRoaming",
   "os": {
    "iOS": {
     "introduced": "5.0",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "Enabled",
     "type": "boolean",
     "required": true
    }
   ]
  },
  "setting.DefaultApplications": {
   "type": "setting.DefaultApplications",
   "family": "command",
   "title": "DefaultApplications",
   "os": {
    "iOS": {
     "introduced": "18.2",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "2.2",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "WebBrowser",
     "type": "string"
    },
    {
     "name": "Calling",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "26.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    },
    {
     "name": "Messaging",
     "type": "string",
     "os": {
      "iOS": {
       "introduced": "26.0"
      },
      "macOS": {
       "introduced": "n/a"
      },
      "tvOS": {
       "introduced": "n/a"
      },
      "visionOS": {
       "introduced": "n/a"
      },
      "watchOS": {
       "introduced": "n/a"
      }
     }
    }
   ]
  },
  "setting.DeviceName": {
   "type": "setting.DeviceName",
   "family": "command",
   "title": "DeviceName",
   "os": {
    "iOS": {
     "introduced": "5.0",
     "supervised": true,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "10.10",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "tvOS": {
     "introduced": "9.0",
     "supervised": false
    },
    "visionOS": {
     "introduced": "2.0",
     "supervised": true,
     "userEnrollment": "forbidden"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "DeviceName",
     "type": "string",
     "required": true
    }
   ]
  },
  "setting.DiagnosticSubmission": {
   "type": "setting.DiagnosticSubmission",
   "family": "command",
   "title": "DiagnosticSubmission",
   "os": {
    "iOS": {
     "introduced": "9.3",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "Enabled",
     "type": "boolean",
     "required": true
    }
   ]
  },
  "setting.HostName": {
   "type": "setting.HostName",
   "family": "command",
   "title": "HostName",
   "os": {
    "iOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "10.11",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "HostName",
     "type": "string",
     "required": true
    }
   ]
  },
  "setting.MaximumResidentUsers": {
   "type": "setting.MaximumResidentUsers",
   "family": "command",
   "title": "MaximumResidentUsers",
   "os": {
    "iOS": {
     "introduced": "9.3",
     "supervised": false,
     "userEnrollment": "forbidden",
     "deprecated": "13.4"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "MaximumResidentUsers",
     "type": "integer",
     "required": true
    }
   ]
  },
  "setting.MDMOptions": {
   "type": "setting.MDMOptions",
   "family": "command",
   "title": "MDMOptions",
   "os": {
    "iOS": {
     "introduced": "7.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "10.15",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "2.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "MDMOptions",
     "type": "dictionary",
     "required": true,
     "subkeys": [
      {
       "name": "ActivationLockAllowedWhileSupervised",
       "type": "boolean"
      },
      {
       "name": "BootstrapTokenAllowed",
       "type": "boolean",
       "os": {
        "iOS": {
         "introduced": "n/a"
        },
        "macOS": {
         "introduced": "10.15",
         "deprecated": "11.0",
         "userEnrollment": "forbidden"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "PromptUserToAllowBootstrapTokenForAuthentication",
       "type": "boolean",
       "os": {
        "iOS": {
         "introduced": "n/a"
        },
        "macOS": {
         "introduced": "11.0"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       }
      },
      {
       "name": "IdleRebootAllowed",
       "type": "boolean",
       "os": {
        "iOS": {
         "introduced": "18.4"
        },
        "macOS": {
         "introduced": "n/a"
        },
        "tvOS": {
         "introduced": "n/a"
        },
        "visionOS": {
         "introduced": "n/a"
        },
        "watchOS": {
         "introduced": "n/a"
        }
       }
      }
     ]
    }
   ]
  },
  "setting.OrganizationInfo": {
   "type": "setting.OrganizationInfo",
   "family": "command",
   "title": "OrganizationInfo",
   "os": {
    "iOS": {
     "introduced": "5.0",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "macOS": {
     "introduced": "10.9",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "9.0",
     "supervised": false
    },
    "visionOS": {
     "introduced": "1.1",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "10.0",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "OrganizationInfo",
     "type": "dictionary",
     "subkeys": [
      {
       "name": "OrganizationName",
       "type": "string",
       "required": true
      },
      {
       "name": "OrganizationShortName",
       "type": "string",
       "os": {
        "iOS": {
         "introduced": "13.0"
        },
        "macOS": {
         "introduced": "10.15"
        },
        "tvOS": {
         "introduced": "13.0"
        }
       }
      },
      {
       "name": "OrganizationAddress",
       "type": "string"
      },
      {
       "name": "OrganizationPhone",
       "type": "string"
      },
      {
       "name": "OrganizationEmail",
       "type": "string"
      },
      {
       "name": "OrganizationMagic",
       "type": "string"
      }
     ]
    }
   ]
  },
  "setting.PasscodeLockGracePeriod": {
   "type": "setting.PasscodeLockGracePeriod",
   "family": "command",
   "title": "PasscodeLockGracePeriod",
   "os": {
    "iOS": {
     "introduced": "9.3.2",
     "supervised": false,
     "userEnrollment": "forbidden",
     "deprecated": "17.0"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "PasscodeLockGracePeriod",
     "type": "integer",
     "required": true,
     "rangelist": [
      0,
      60,
      300,
      900,
      3600,
      14400
     ]
    }
   ]
  },
  "setting.PersonalHotspot": {
   "type": "setting.PersonalHotspot",
   "family": "command",
   "title": "PersonalHotspot",
   "os": {
    "iOS": {
     "introduced": "5.0",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "Enabled",
     "type": "boolean",
     "required": true
    }
   ]
  },
  "setting.SharedDeviceConfiguration": {
   "type": "setting.SharedDeviceConfiguration",
   "family": "command",
   "title": "SharedDeviceConfiguration",
   "os": {
    "iOS": {
     "introduced": "13.4",
     "supervised": false,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "QuotaSize",
     "type": "integer"
    },
    {
     "name": "ResidentUsers",
     "type": "integer"
    },
    {
     "name": "UserSessionTimeout",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "14.5"
      }
     }
    },
    {
     "name": "TemporarySessionTimeout",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "14.5"
      },
      "visionOS": {
       "introduced": "26.0",
       "supervised": true
      }
     }
    },
    {
     "name": "TemporarySessionOnly",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "14.5"
      }
     }
    },
    {
     "name": "ManagedAppleIDDefaultDomains",
     "type": "array",
     "os": {
      "iOS": {
       "introduced": "16.0"
      }
     },
     "subkeys": [
      {
       "name": "AppleID domain",
       "type": "string"
      }
     ]
    },
    {
     "name": "OnlineAuthenticationGracePeriod",
     "type": "integer",
     "os": {
      "iOS": {
       "introduced": "16.0"
      }
     }
    },
    {
     "name": "SkipLanguageAndLocaleSetupForNewUsers",
     "type": "boolean",
     "os": {
      "iOS": {
       "introduced": "16.2"
      }
     }
    },
    {
     "name": "AwaitUserConfiguration",
     "type": "dictionary",
     "os": {
      "iOS": {
       "introduced": "17.0"
      }
     },
     "subkeys": [
      {
       "name": "Enabled",
       "type": "boolean",
       "required": true
      }
     ]
    },
    {
     "name": "PasscodePolicy",
     "type": "dictionary",
     "os": {
      "iOS": {
       "introduced": "17.0"
      }
     },
     "subkeys": [
      {
       "name": "PasscodeLockGracePeriod",
       "type": "integer",
       "rangelist": [
        0,
        60,
        300,
        900,
        3600,
        14400
       ]
      },
      {
       "name": "AutoLockTime",
       "type": "integer"
      }
     ]
    }
   ]
  },
  "setting.SoftwareUpdateSettings": {
   "type": "setting.SoftwareUpdateSettings",
   "family": "command",
   "title": "SoftwareUpdateSettings",
   "os": {
    "iOS": {
     "introduced": "14.5",
     "supervised": true,
     "userEnrollment": "forbidden",
     "deprecated": "26.0",
     "removed": "27.0"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "RecommendationCadence",
     "type": "integer",
     "required": true,
     "rangelist": [
      0,
      1,
      2
     ]
    }
   ]
  },
  "setting.TimeZone": {
   "type": "setting.TimeZone",
   "family": "command",
   "title": "TimeZone",
   "os": {
    "iOS": {
     "introduced": "14.0",
     "supervised": true,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "14.0",
     "supervised": true
    },
    "visionOS": {
     "introduced": "2.0",
     "supervised": true,
     "userEnrollment": "forbidden"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "TimeZone",
     "type": "string",
     "required": true
    }
   ]
  },
  "setting.VoiceRoaming": {
   "type": "setting.VoiceRoaming",
   "family": "command",
   "title": "VoiceRoaming",
   "os": {
    "iOS": {
     "introduced": "5.0",
     "supervised": false,
     "userEnrollment": "forbidden",
     "deprecated": "16.0"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "Enabled",
     "type": "boolean",
     "required": true
    }
   ]
  },
  "setting.Wallpaper": {
   "type": "setting.Wallpaper",
   "family": "command",
   "title": "Wallpaper",
   "os": {
    "iOS": {
     "introduced": "8.0",
     "supervised": true,
     "userEnrollment": "forbidden"
    },
    "macOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "tvOS": {
     "introduced": "n/a",
     "supervised": false
    },
    "visionOS": {
     "introduced": "n/a",
     "supervised": false,
     "userEnrollment": "allowed"
    },
    "watchOS": {
     "introduced": "n/a",
     "supervised": false
    }
   },
   "keys": [
    {
     "name": "Image",
     "type": "data",
     "required": true
    },
    {
     "name": "Where",
     "type": "integer",
     "required": true,
     "rangelist": [
      1,
      2,
      3
     ]
    }
   ]
  }
 }
};
