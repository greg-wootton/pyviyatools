#!/usr/bin/env python3
# Script to move or merge user folders from an old to new user ID provider in arguments (single user) or through a CSV.

# Import required packages
import argparse
import logging
import csv
import sys
from sharedfunctions import callrestapi, callpagedrestapi

# Define argument parser for command-line arguments
parser = argparse.ArgumentParser(
    description="Move or merge user folders from an old to new user ID provider."
)
parser.add_argument("--old-user", help="Old user ID")
parser.add_argument("--new-user", help="New user ID")
parser.add_argument("--csv", help="CSV file containing old and new user IDs")
parser.add_argument(
    "--merge",
    action="store_true",
    help="Merge folders instead of just setting permissions on them",
)
parser.add_argument(
    "--dry-run",
    action="store_true",
    help="Log actions without making changes",
)
args = parser.parse_args()

# Configure a basic logger to output timestamp/level/message.
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Evaluate supplied arguments, only one method of input should be used at a time (either command-line arguments or CSV). Both
# old and new user must be specified when being used.
if (args.old_user and not args.new_user) or (args.new_user and not args.old_user):
    logger.error("Both --old-user and --new-user must be specified together.")
    parser.print_help()
    exit(1)
if args.csv and (args.old_user or args.new_user):
    logger.error("Specify either command-line arguments or a CSV file, not both.")
    parser.print_help()
    exit(1)
if not args.csv and not (args.old_user and args.new_user):
    logger.error("You must specify either command-line arguments or a CSV file.")
    parser.print_help()
    exit(1)

# Helper functions

## Validate User - Call identities service to confirm the user exists. This will return the ID as it is defined in identities (for rules purposes)
def validate_user(user_id):
    reqtype = "head"
    reqval = "/identities/users/" + user_id
    response,status_code = callrestapi(reqval, reqtype)
    if status_code == 404:
        logger.error(f"User '{user_id}' does not exist.")
        exit(1)
    return response.get("id")

## Get User Folder - Get the folder for a specific user by their ID
def get_user_folder_id(user_id):
    # The folders service creates folders with the user ID normalized (lowercase).
    user_id_normal=user_id.lower()
    reqtype = "get"
    reqval = "/folders/folders"
    filter = f"and(eq(type,'userFolder'),or(eq(name,'{user_id}'),eq(name,'{user_id_normal}')))"
    params = {"filter": filter}
    # Check if the object
    response = callrestapi(reqval, reqtype, params=params)
    # If the response returns more than one item, fail.
    if response.get("items") and len(response.get("items")) > 1:
        logger.error(f"Multiple user folders found for user '{user_id}'.")
        exit(1)
    return response.get("items")[0].get("id") if response.get("items") else None


## Create Rule - Given a folder ID and user ID, grant normal permissions to the user on the folder
def create_rule(folder_id, user_id):

    ident_user_id = validate_user(user_id)
    if ident_user_id != user_id:
        logger.warn(f"Supplied user ID '{user_id}' does not match Identities service record. Expected '{ident_user_id}', got '{user_id}'.")

    # Confirm a rule does not already exist for this user/folder.
    reqtype = "get"
    reqval = "/authorization/rules"
    params = {
        "filter": f"and(or(eq(containerUri,'/folders/folders/{folder_id}'),eq(objectUri,'/folders/folders/{folder_id}/**')),eq(principal,'{ident_user_id}'))"
    }
    response = callrestapi(reqval, reqtype, params=params)
    if response.get("items") and len(response.get("items")) > 0:
        logger.info(
            f"Rule already exists for user '{ident_user_id}' on folder '{folder_id}'."
        )
        return None

    reqtype = "post"
    reqval = "/authorization/rules"
    data = {
        "containerUri": f"/folders/folders/{folder_id}",
        "objectUri": f"/folders/folders/{folder_id}/**",
        "type": "grant",
        "principal": ident_user_id,
        "principalType": "user",
        "permissions": ["delete", "read", "secure", "remove", "update", "add"],
        "description": f"Created by mergeuserfolders pyviyatools to grant {ident_user_id} permission on the folder.",
        "reason": f"Granting {ident_user_id} permission on the folder.",
    }
    if args.dry_run:
        logger.info(
            f"DRY-RUN: Would create authorization rule for user '{ident_user_id}' on folder '{folder_id}'."
        )
        return "dry-run"

    response = callrestapi(reqval, reqtype, data=data)
    return response.get("id") if response else None


## Update Rule - Given a folder ID, old user ID and new user ID, locates the existing rule for the old user ID and replaces the principal with the new user ID.
def update_rule(folder_id, old_user_id, new_user_id):
    # We might not be able to find the old user in identities to validate, but we should do this for the new user.
    ident_new_user_id = validate_user(new_user_id)
    if ident_new_user_id != new_user_id:
        logger.warn(f"Supplied new user ID '{new_user_id}' does not match Identities service record. Expected '{ident_new_user_id}', got '{new_user_id}'.")
        

    # Locate the existing rule for the old user
    reqtype = "get"
    reqval = "/authorization/rules"
    params = {
        "filter": f"and(eq(containerUri,'/folders/folders/{folder_id}'),eq(objectUri,'/folders/folders/{folder_id}/**'),eq(principal,'{old_user_id}'))"
    }
    response = callrestapi(reqval, reqtype, params=params)
    if not response.get("items") or len(response.get("items")) == 0:
        logger.error(
            f"No existing rule found for old user '{old_user_id}' on folder '{folder_id}'."
        )
        sys.exit(1)
    # Fail if we got more than one rule for the old user on this folder.
    if len(response.get("items")) > 1:
        logger.error(
            f"Multiple existing rules found for old user '{old_user_id}' on folder '{folder_id}'."
        )
        sys.exit(1)
    existing_rule = response.get("items")[0]

    # The existing rule response is going to include some things we don't need (creationTimestamp, modifiedTimestamp, createdBy, modifiedBy, and the links)
    # We can drop those and then replace the principal old user with the new user.

    existing_rule_copy = existing_rule.copy()

    for key in [
        "creationTimestamp",
        "modifiedTimestamp",
        "createdBy",
        "modifiedBy",
        "links",
        "id",
    ]:
        existing_rule_copy.pop(key, None)
    existing_rule_copy["principal"] = ident_new_user_id

    reqtype = "put"
    reqval = f"/authorization/rules/{existing_rule.get('id')}"
    if args.dry_run:
        logger.info(
            f"DRY-RUN: Would update authorization rule '{existing_rule.get('id')}' principal from '{old_user_id}' to '{ident_new_user_id}'."
        )
        return "dry-run"

    response = callrestapi(reqval, reqtype, data=existing_rule_copy)
    return response.get("id") if response else None


## Validate Member Name - This confirms we won't encounter a naming conflict before actually trying to rename a folder. The parent_id would be the new parent folder ID and member_id would be "@new" to indicate we are not renaming an existing member.
def validate_member_name(
    parent_id, member_id="@new", member_type=None, type_def_name=None, object_name=None
):
    reqtype = "put"
    reqval = f"/commons/validations/folders/{parent_id}/members/{member_id}/name"
    if type_def_name is None:
        params = {"value": object_name, "type": member_type}
    else:
        params = {
            "value": object_name,
            "type": member_type,
            "typeDefName": type_def_name,
        }
    response = callrestapi(reqval, reqtype, params=params)
    return response.get("valid") if response else False


## Rename Folder - Given a folder ID and a new name, rename the folder.
def rename_folder(folder_id, new_name):

    # Get the etag for the folder
    reqtype = "head"
    reqval = f"/folders/folders/{folder_id}"
    response, etag, status_code = callrestapi(reqval, reqtype, returnEtag=True)

    # Rename the folder using a PATCH request
    reqtype = "patch"
    reqval = f"/folders/folders/{folder_id}"
    data = {"name": new_name}
    if args.dry_run:
        logger.info(
            f"DRY-RUN: Would rename folder '{folder_id}' to '{new_name}'."
        )
        return folder_id

    response = callrestapi(reqval, reqtype, data=data, etagIn=etag)
    return response.get("id") if response else None


## Get folder members - Get all members of a folder recursively.
def get_folder_members(folder_id):
    reqtype = "get"
    reqval = f"/folders/folders/{folder_id}/members"
    response = callpagedrestapi(reqval, reqtype)
    return response if response else []


def merge_folders(old_folder_id, new_folder_id):
    logger.info(f"Merging folder '{old_folder_id}' into folder '{new_folder_id}'.")

    # Get all members of the old folder recursively
    old_folder_members = get_folder_members(old_folder_id)
    new_folder_members = get_folder_members(new_folder_id)

    # Each member item has the following attributes:
    # creationTimeStamp, createdBy, modifiedTimeStamp, modifiedBy, version, id (this is the ID of the membership), name, parentFolderUri, uri, type, contentType, and (optionally) typeDefName, and a links array.
    # There are special "delegate" folders at the top level, which have contentTypes: "trashFolder", "favoritesFolder", "applicationDataFolder", "myFolder" and "historyFolder". These cannot be moved, but should exist in the destination.
    # The valid "types" for folder members are "child" and "reference". A "child" type can only be a member of one folder, while a "reference" is a shortcut, so it's URI may not even refer to something in the environment.
    # Name uniqueness is enforced within a folder for a given type (so you could have a child and reference with the same name but not two child objects or two reference objects with the same name.)
    # Our validate_member_name function can be used to check for naming conflicts before attempting to move a folder member. We'll skip any move that would result in a conflict.
    # Nested folders show as contentType "folder". If a folder with the same name already exists in the destination, we should merge the contents of the old folder into the existing folder in the destination. We'll need recursion here
    # In case that folder contains a folder that already exists in the destination. If the folder doesn't exist we can move the whole thing (with the exception of the delegate folders, which are immovable).
    # There are two ways to effect a move.
    # 1. A PUT request on /folders/folders/{folder_id}/members/{member_id}, specifying a new parentFolderUri will effect a move. The PUT should include the full member details with only the parentFolderUri changed.
    # 2. A PATCH request on /folder/folders/@item, specifying the childUri and new parentFolderUri as query parameters. This is useful for moving a member without needing to provide the full member details, but can't be used for reference type members.

    # For each old folder member...
    for member in old_folder_members:
        # Grab our attributes for the member:
        member_id = member.get("id")
        member_name = member.get("name")
        member_uri = member.get("uri")
        member_type = member.get("type")
        member_typedef_name = member.get("typeDefName")
        member_content_type = member.get("contentType")

        # Split our process up for references versus child types:
        if member_type == "reference":
            # Validate the member name in the new folder to avoid naming conflicts
            if not validate_member_name(
                new_folder_id,
                member_id=member_id,
                member_type=member_type,
                type_def_name=member_typedef_name,
                object_name=member_name,
            ):
                logger.error(
                    f"Naming conflict detected for reference '{member_name}' in folder '{new_folder_id}'. Aborting merge."
                )
                sys.exit(1)

            # Move the reference to the new folder.
            reqtype = "put"
            reqval = f"/folders/folders/{old_folder_id}/members/{member_id}"
            member_copy = member.copy()
            member_copy["parentFolderUri"] = f"/folders/folders/{new_folder_id}"
            if args.dry_run:
                logger.info(
                    f"DRY-RUN: Would move reference '{member_name}' from folder '{old_folder_id}' to folder '{new_folder_id}'."
                )
            else:
                callrestapi(reqval, reqtype, data=member_copy)
                logger.info(
                    f"Moved reference '{member_name}' from folder '{old_folder_id}' to folder '{new_folder_id}'."
                )
            continue
        elif member_type == "child":
            # If it's a delegate folder, we need to run this same function against it. We need to identify the folder ID of the same content type folder in the new_folder_members list to do that. The folder ID can be extracted from the URI.
            if member_content_type in [
                "trashFolder",
                "favoritesFolder",
                "applicationDataFolder",
                "myFolder",
                "historyFolder",
            ]:
                old_delegate_folder_id = member_uri.split("/")[-1]
                corresponding_new_member = next(
                    (
                        m
                        for m in new_folder_members
                        if m.get("contentType") == member_content_type
                    ),
                    None,
                )
                if corresponding_new_member:
                    new_delegate_folder_id = corresponding_new_member.get("uri").split(
                        "/"
                    )[-1]
                    merge_folders(old_delegate_folder_id, new_delegate_folder_id)
                else:
                    logger.error(
                        f"No corresponding new member found for delegate folder '{member_content_type}' in folder '{new_folder_id}'. Aborting merge."
                    )
                    sys.exit(1)
                continue

            # If it's a folder, we need to check if a folder with the same name exists in the new folder. If it does, we merge them; if not, we move the old folder to the new location.
            elif member_content_type == "folder":
                old_member_folder_id = member_uri.split("/")[-1]
                corresponding_new_member = next(
                    (
                        m
                        for m in new_folder_members
                        if m.get("contentType") == "folder"
                        and m.get("name") == member_name
                    ),
                    None,
                )
                if corresponding_new_member:
                    new_member_folder_id = corresponding_new_member.get("uri").split(
                        "/"
                    )[-1]
                    merge_folders(old_member_folder_id, new_member_folder_id)
                else:
                    # Validate that moving the folder won't cause a naming conflict (this shouldn't happen because we just looked for a member with that name to merge recursively)
                    if not validate_member_name(
                        new_folder_id,
                        member_type=member_type,
                        type_def_name=member_typedef_name,
                        object_name=member_name,
                    ):
                        logger.error(
                            f"Naming conflict detected for folder '{member_name}' in folder '{new_folder_id}'. Aborting merge."
                        )
                        sys.exit(1)
                    # Move the old folder to the new location
                    reqtype = "put"
                    reqval = f"/folders/folders/{old_folder_id}/members/{member_id}"
                    member_copy = member.copy()
                    member_copy["parentFolderUri"] = f"/folders/folders/{new_folder_id}"
                    if args.dry_run:
                        logger.info(
                            f"DRY-RUN: Would move folder '{member_name}' from folder '{old_folder_id}' to folder '{new_folder_id}'."
                        )
                    else:
                        callrestapi(reqval, reqtype, data=member_copy)

            else:
                # Here we handle all the non-folder child members.
                if not validate_member_name(
                    new_folder_id,
                    member_id=member_id,
                    member_type=member_type,
                    type_def_name=member_typedef_name,
                    object_name=member_name,
                ):
                    logger.error(
                        f"Naming conflict detected for non-folder child member '{member_name}' in folder '{new_folder_id}'. Aborting merge."
                    )
                    sys.exit(1)
                reqtype = "put"
                reqval = f"/folders/folders/{old_folder_id}/members/{member_id}"
                member_copy = member.copy()
                member_copy["parentFolderUri"] = f"/folders/folders/{new_folder_id}"
                if args.dry_run:
                    logger.info(
                        f"DRY-RUN: Would move non-folder child member '{member_name}' from folder '{old_folder_id}' to folder '{new_folder_id}'."
                    )
                else:
                    callrestapi(reqval, reqtype, data=member_copy)
                    logger.info(
                        f"Moved non-folder child member '{member_name}' from folder '{old_folder_id}' to folder '{new_folder_id}'."
                    )
                continue

    return True
# End Helper functions

def main():
    if args.dry_run:
        logger.info("Running in dry-run mode; no changes will be made.")

    # Scenarios we need to handle:
    # 1. User has never logged in (no old or new user folder -- no action needed)
    # 2. User has only logged in as new user (no old folder -- no action needed)
    # 3. User has only logged in as old user (no new folder -- rename old folder and update existing rule)
    # 4. User has logged in as both old and new user (merge old folder into new folder or create a new rule on old folder granting new user access)

    # Build a list of identities to process either from the CSV or a list of one entry from the options:
    identities = []
    if args.csv:
        with open(args.csv, newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                identities.append(
                    {
                        "old_user_id": row.get("old_user_id"),
                        "new_user_id": row.get("new_user_id"),
                    }
                )
    else:
        identities.append(
            {
                "old_user_id": args.old_user,
                "new_user_id": args.new_user,
            }
        )

    # Process each identity
    for identity in identities:

        old_user_id = identity.get("old_user_id")
        new_user_id = identity.get("new_user_id")

        if not old_user_id or not new_user_id:
            logger.warning(f"Missing old or new user ID for identity: {identity}")
            continue

        logger.info(f"Processing identity pair: '{old_user_id}' -> '{new_user_id}'")

        old_user_folder_id = get_user_folder_id(old_user_id)

        if not old_user_folder_id:
            # Scenario 1 or 2: No old user folder, no action needed
            logger.info(f"No old user folder found for '{old_user_id}'. Skipping.")
            continue

        new_user_folder_id = get_user_folder_id(new_user_id)

        if not new_user_folder_id:
            # Scenario 3: Only old user folder exists, rename it and update the rule
            logger.info(
                f"No new user folder found for '{new_user_id}'. Renaming old user folder and updating rule."
            )
            new_user_id_normal=new_user_id.lower()
            rename_folder(old_user_folder_id, new_user_id_normal)
            update_rule(old_user_folder_id, old_user_id, new_user_id)
            continue

        # Scenario 4: Both old and new user folders exist, merge if merge is set or if not, add rule for the old folder.
        if args.merge:
            merge_folders(old_user_folder_id, new_user_folder_id)
        else:
            create_rule(old_user_folder_id, new_user_id)


if __name__ == "__main__":
    main()