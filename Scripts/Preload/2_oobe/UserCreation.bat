net user "User" "" /add

net localgroup "Administratoren" "User" /add

WMIC USERACCOUNT WHERE "Name='User'" SET PasswordExpires=FALSE
