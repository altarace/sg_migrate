'''
Migrate security groups from classic/vpc to vpc

Usage:
    python <script> [options]
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
        The destination VPC_ID into which the security groups will be created'

    -r, --destinationregion=region_id
        The region in which security groups will be created in
        Default:us-east-1

    -x, --dryrun (not implemented yet)
        Only display changes; do not write
        Default:false

    -o, --overwrite (not yet implemented)
        Overwrite existing security groups with the same name in the destination vpc
        Default:false
'''
import boto.ec2
import boto.vpc
import re
import sys
from collections import defaultdict
import getopt
import json

class sgh:
    def __init__(self, id, name, origsg):
        self.ID = id
        self.name = name
        self.sg = origsg
        self.dep_list = []
        self.newsg = None
        self.newsgID = None
    def search(self, searchid):
        retval = None
        if self.ID == searchid:
            retval = self
        elif self.dep_list:
            for item in self.dep_list:
                retval = item.search(searchid)
                if retval is not None:
                    break
        return retval
    def searchnew(self, searchid):
        retval = None
        if self.newsgID == searchid:
            retval = self
        elif self.dep_list:
            for item in self.dep_list:
                retval = item.searchnew(searchid)
                if retval is not None:
                    break
        return retval
    def __str__(self):
        return"sg: "+str(self.name)+"("+str(self.ID)+")"+"***"+str(self.dep_list)+"\n"
    def __repr__(self):
        return self.__str__()

class missing:
    def __init__(self, id, parent,name, origsg):
        self.ID = id
        self.name = name
        self.sg = origsg
        self.parent = parent
    def __str__(self):
        return"missings dependant:"+str(self.parent)+" For SG"+str(self.name)
    def __repr__(self):
        return self.__str__()

def migrate_sg(source, soureceregion, dest, desregion,overwrite, test):
    #print >>sys.stderr, source, soureceregion, dest, desregion, overwrite, test
    #boto.set_stream_logger('boto')
    conn = boto.ec2.connect_to_region(sourceregion)
    sourcefilter = None
    source_security_groups = None
    if source is not "classic":
        sourcefilter = {'vpc-id': source}
        source_security_groups = conn.get_all_security_groups(filters=sourcefilter)
    else:
        source_security_groups = conn.get_all_security_groups()
        source_security_groups = [classicgroup for classicgroup in source_security_groups if classicgroup.vpc_id is None]
    assert source_security_groups is not None, "Did not find security groups"
    #print >>sys.stderr, source_security_groups
    sg_trees = []
    orphans = []
    for sg in source_security_groups:
        foundParent = False
        for rule in sg.rules:
                    for parents in rule.grants:
                            for sgname in source_security_groups:
                                if sgname.name == parents.name: #if parents.name in source_security_groups:
                                    if parents.name != sg.name:
                                        foundParent = True
                                        found_id = None
                                        for sg_review in sg_trees:
                                            found_id = sg_review.search(parents.group_id)
                                            if found_id:
                                                found_id.dep_list.append(sgh(sg.id,sg.name, sg))
                                                break
                                        if not found_id:
                                                orphans.append(missing(sg.id,parents.group_id,sg.name,sg))


        if foundParent is False:
            sg_trees.append(sgh(sg.id,sg.name,sg))
    while orphans:
        #print >>sys.stderr, "dependancies without parent security group:", repr(orphans)
        found_id = None
        for lost in orphans:
            for sg_review in sg_trees:
                found_id = sg_review.search(lost.parent)
                if found_id:
                    break
        if found_id:
            found_id.dep_list.append(sgh(lost.ID,lost.name,lost.sg))
            idx = orphans.index(lost)
            orphans.pop(idx)

    #print >>sys.stderr, repr(sg_trees)
    assert sg_trees is not None, "No SG dependency tree"
    #while sg_trees:
    new_conn = boto.ec2.connect_to_region(desregion)
    for sgs in sg_trees:
        if sgs.name != 'default':
            create_new_sg(sgs, desregion,dest,sg_trees,new_conn)


def create_new_sg(sg_def, destregion, dest, orig_trees,new_conn):
    try:
        new_sg = new_conn.create_security_group(sg_def.sg.name, sg_def.sg.description, dest)
    except boto.exception.BotoServerError as e:
        if (e.status == 400 and e.error_code == 'InvalidGroup.Duplicate'):
            for item in sg_def.dep_list:
                create_new_sg(item, destregion, dest, orig_trees,new_conn)
        else:
            print >>sys.stderr, e
        return
    sg_def.newsg = new_sg
    sg_def.newsgID = new_sg.id
    for rules in sg_def.sg.rules:
        for grant in rules.grants:
            params = {
                'ip_protocol': rules.ip_protocol,
                'from_port': rules.from_port,
                'to_port': rules.to_port
            }
            try:
                parent_id = grant.group_id
                if parent_id == None:
                    raise AttributeError
                parent_group = None
                for nsg_review in orig_trees:
                    parent_group = nsg_review.search(parent_id)
                    if parent_group:
                        break
                if not parent_group:
                    raise "cannot find parent security group"
                params['src_group'] = parent_group.newsg

            except AttributeError:
                params['cidr_ip'] = grant.cidr_ip
            new_sg.authorize(**params)

    for item in sg_def.dep_list:
        create_new_sg(item, destregion, dest, orig_trees,new_conn)


#
# main
#

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

if __name__ == "__main__":
    try:
        try:
            opts, args = getopt.getopt(sys.argv[1:], 's:d:u:r:xoh', ["source=","destination=","dryrun","overwrite","sourceregion=","destinationregion=","help"])
        except getopt.error, msg:
             raise Usage(msg)

        # Handle options
        source="classic"
        sourceregion = "us-east-1"
        destregion = "us-east-1"
        destination = None
        overwrite = False
        dryrun = False

        for option, value in opts:
            if option in ("-h", "--help"):
                print __doc__
                sys.exit(0)
            elif option in ("-s", "--source"):
                source = value
            elif option in ("-u", "--sourceregion"):
                sourceregion = value
            elif option in ("-d", "--destination"):
                destination = value
            elif option in ("-r", "--destinationregion"):
                destregion = value
            elif option in ("-x", "--dryrun"):
                dryrun = True
            elif option in ("-o", "--overwrite"):
                overwrite = True
            else:
                raise Usage('unhandled option "%s"' % option)

        # Handle arguments
        n_args = len(args)
        if n_args > 0:
            raise Usage("invalid number of arguments")
        if destination is None:
            raise Usage("must specify vpc id as destination")
        # Doit
        migrate_sg(source,sourceregion,destination, destregion,overwrite, dryrun)

    except Usage, err:
        print >>sys.stderr, err.msg
        print >>sys.stderr, "for help use --help"
        sys.exit(2)
    except Exception, err:
        print >>sys.stderr, err
        sys.exit(1)
    else:
        sys.exit(0)