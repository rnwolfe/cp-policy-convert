# cp-policy-convert
This perl script was created to take an XML export of a Checkpoint firewall (not sure of version at the time) and convert it's objects and policies to Cisco ASA command line syntax. It is made to be a migration tool because the one Cisco provided did not get the job done in the way I needed. The primary difference in that Checkpoints use a global policy and ASAs use a per-interface policy. This script adds a step to have the user specify an interface name to apply each rule too from the existing Checkpoint policy.

* Step 1: Specify XML export files, and where to put the generated CSV.
* Step 2: Use the CSV and specify the interface name that each rule should be applied to (a manual process, but it's all that I needed at the time)
* Step 3: Use the script with the CSV and generate the config.

Note: The syntax is available in the script, or just by running ./policy-convert1.0.pl with no options.

From script:
```
# Usage:
#       If the rule -> interface mapping CSV has been generated already, generate the converted config with:
#               policy-convert.pl <policy xml file> <service xml file> <network xml file> <rule-interface mapping csv> <FW name>
#       If the rule -> interface mapping CSV still needs to be created, create it with:
#               policy-convert.pl -csv <policy xml file> <network xml file> <FW name>
#
# This script does not successfully convert all rules properly. The following types of rules will be converted, but not 
# properly:
# - Time based access rules
#               * This can be done on ASA, but will need to be done manually.
# - Rules that say "NOT (object)" e.g. Permit all traffic from internal networks that is a approved-internet-port and is NOT
#   destined for a private network.
#               * The ASA does not support negatively referencing a src/dest object. In order to fix this, you will need to manually
#                 create the rule referencing the inverse destination.
```

This was really just created for my specific case and not for general use, but please use it as suits your needs.

-W
