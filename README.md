# cp-policy-convert
This perl script was created to take an XML export of a Checkpoint firewall (not sure of version at the time) and convert it's objects and policies to Cisco ASA command line syntax. It is made to be a migration tool because the one Cisco provided did not get the job done in the way I needed. The primary difference in that Checkpoints use a global policy and ASAs use a per-interface policy. This script adds a step to have the user specify an interface name to apply each rule too from the existing Checkpoint policy.

Step 1: Specify XML export files, and where to put the generated CSV.
Step 2: Use the CSV and specify the interface name that each rule should be applied to (a manual process, but it's all that I needed at the time)
Step 3: Use the script with the CSV and generate the config.

* The syntax is available in the script, or just by running ./policy-convert1.0.pl with no options.

This was really just created for my specific case and not for general use, but please use it as suits your needs.

-R
