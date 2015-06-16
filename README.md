# sg_migrate
This script will recreate the security group structure in the source environment (either ec2 classic or a VPC) on the
target environment (destination VPC) including dependencies between security groups 


Usage:
    python sg_migrate.py [options] <br><br>
Options:
    -h, --help
        Print this help information

    -s, --source=VPC_ID/"classic"
        The source from which to copy security groups "classic" for classic or VPC_ID for a VPC
        Default:"classic"
    -u, --sourceregion=region_id
        The region in which source security groups will be loaded from
        Default:us-east-1

    -d, --destination=VPC_ID
        The destination VPC_ID into which the security groups will be created

    -r, --destinationregion=region_id
        The region in which security groups will be created in
        Default:us-east-1

    -x, --dryrun (not implemented yet)
        Only display changes; do not write
        Default:false

    -o, --overwrite (not yet implemented)
        Overwrite existing security groups with the same name in the destination vpc
        Default:false
        
        
    TODO:
    * make code less "javay" and more "pythony"
    * implement overwrite
    * implement dry-run
    * add prefix to new SG names (e.g. dev-, qa-)
    * different source/target accounts
