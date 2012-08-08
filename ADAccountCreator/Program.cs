using System.DirectoryServices;
using System;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
namespace AdAccountCreator
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("What is the room number you want?");
            string roomNumber = Console.ReadLine();
            if (roomNumber != "2E20")
            {
                for (int i = 01; i < 35; i++)
                {
                    if (i < 10)
                    {
                        string a = ("0" + i);
                        string userName = "BT_" + roomNumber + "_" + a;
                        System.Console.WriteLine(CreateUserAccount(userName, "", roomNumber));
                        System.Console.WriteLine(userName);
                    }
                    else if (i < 35)
                    {
                        string userName = "BT_" + roomNumber + "_" + i;
                        System.Console.WriteLine(CreateUserAccount(userName, "", roomNumber));
                        System.Console.WriteLine(userName);
                    }
                }
            }
            else
            {
                for (int i = 01; i < 69; i++)
                {
                    if (i < 10)
                    {
                        string a = ("0" + i);
                        string userName = "BT_" + roomNumber + "_" + a;
                        System.Console.WriteLine(CreateUserAccount(userName, "", roomNumber));
                        System.Console.WriteLine(userName);
                    }
                    else
                    {
                        string userName = "BT_" + roomNumber + "_" + i;
                        System.Console.WriteLine(CreateUserAccount(userName, "", roomNumber));
                        System.Console.WriteLine(userName);
                    }

                }
            }
        }

        public static string CreateUserAccount(string userName,
    string userPassword, string roomNumber)
        {
            try
            {
                string ldapPath = "bktech.local/OU=" + roomNumber + " User,DC=bktech,DC=local";
                string oGUID = string.Empty;
                string connectionPrefix = "LDAP://" + ldapPath;
                DirectoryEntry dirEntry = new DirectoryEntry(connectionPrefix);
                DirectoryEntry newUser = dirEntry.Children.Add
                    ("CN=" + userName, "user");
                newUser.Properties["samAccountName"].Value = userName;
                newUser.CommitChanges();
                oGUID = newUser.Guid.ToString();

                newUser.Invoke("SetPassword", new object[] { userPassword });
                DontExpirePassword(newUser);
                DenyChangePassword(newUser);
                SetProperty(newUser, "userWorkstations", userName);
                newUser.CommitChanges();
                dirEntry.Close();
                newUser.Close();
                return oGUID;
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException E)
            {
                //DoSomethingwith --> E.Message.ToString();
                System.Console.WriteLine(E.Message.ToString());
                return "Error";
            }

        }
        static void DontExpirePassword(DirectoryEntry User)
        {
            int val;
            const int ADS_UF_DONT_EXPIRE_PASSWD = 0x10000;
            val = (int)User.Properties["userAccountControl"].Value;
            User.Properties["userAccountControl"].Value = val |
                ADS_UF_DONT_EXPIRE_PASSWD;
            User.CommitChanges();
        }
        static void DenyChangePassword(DirectoryEntry user)
        {
            // Create a Guid that identifies the Change Password right.
            Guid changePasswordGuid =
                new Guid("{AB721A53-1E2F-11D0-9819-00AA0040529B}");

            // Get the ActiveDirectorySecurity for the user.
            ActiveDirectorySecurity userSecurity = user.ObjectSecurity;

            // Create a SecurityIdentifier object for "everyone".
            SecurityIdentifier everyoneSid =
                new SecurityIdentifier(WellKnownSidType.WorldSid, null);

            // Create a SecurityIdentifier object for "self".
            SecurityIdentifier selfSid =
                new SecurityIdentifier(WellKnownSidType.SelfSid, null);

            // Create an access rule to allow everyone the change password 
            // right. 
            // This is used to remove any existing access rules.
            ActiveDirectoryAccessRule allowEveryone =
                new ActiveDirectoryAccessRule(
                    everyoneSid,
                    ActiveDirectoryRights.ExtendedRight,
                    AccessControlType.Allow,
                    changePasswordGuid);

            // Create an access rule to deny everyone the change password right.
            ActiveDirectoryAccessRule denyEveryone =
                new ActiveDirectoryAccessRule(
                    everyoneSid,
                    ActiveDirectoryRights.ExtendedRight,
                    AccessControlType.Deny,
                    changePasswordGuid);

            // Create an access rule to allow self the change password right.
            // This is used to remove any existing access rules.
            ActiveDirectoryAccessRule allowSelf =
                new ActiveDirectoryAccessRule(
                    selfSid,
                    ActiveDirectoryRights.ExtendedRight,
                    AccessControlType.Allow,
                    changePasswordGuid);

            // Create an access rule to deny self the change password right.
            ActiveDirectoryAccessRule denySelf =
                new ActiveDirectoryAccessRule(
                    selfSid,
                    ActiveDirectoryRights.ExtendedRight,
                    AccessControlType.Deny,
                    changePasswordGuid);

            // Remove any existing rule that gives "everyone" the change 
            // password right.
            userSecurity.RemoveAccessRuleSpecific(allowEveryone);

            // Add a new access rule to deny "everyone" the change password 
            // right.
            userSecurity.AddAccessRule(denyEveryone);

            // Remove any existing rule that gives "self" the change password 
            // right.
            userSecurity.RemoveAccessRuleSpecific(allowSelf);

            // Add a new access rule to deny "self" the change password right.
            userSecurity.AddAccessRule(denySelf);

            // Commit the changes.
            user.CommitChanges();
        }
        static void SetProperty(DirectoryEntry oDE, string sPropertyName, string sPropertyValue)
        {
            //Check if the Value is Valid
            if (sPropertyValue != string.Empty)
            {
                //Check if the Property Exists
                if (oDE.Properties.Contains(sPropertyName))
                {
                    oDE.Properties[sPropertyName].Value = sPropertyValue;
                    oDE.CommitChanges();
                    oDE.Close();
                }
                else
                {
                    oDE.Properties[sPropertyName].Add(sPropertyValue);
                    oDE.CommitChanges();
                    oDE.Close();
                }
            }
        }
    }
}
