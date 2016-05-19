# Lychee-security
Add an extra layer of security to Lychee

## Installation

The file `SecurityPlugin.php` must be placed in the directory `Lychee/plugins/Security/`. Then, in the table _lychee_settings_, `Security\SecurityPlugin` must be added to the _plugins_ key ([as explained here](https://github.com/electerious/Lychee/blob/master/docs/Plugins.md#how-to-create-a-plugin)). The plugin is now activated.

## Settings

You can modify the following settings in the `SecurityPlugin.php` file.

| Name | Description |
|:-----------|:------------|
| $whitelistIps | Array of IPs to put on whitelist. A whitelisted IP won't get blocked in any case. |
| $blacklistIps | Array of IPs to blacklist. A blacklisted IP can't access the website. |
| $maxNumberOfAttempts | Maximum number of failed attempts before an IP gets blocked. |
| $resetAttemptTime | Time (in seconds) during which attempts are counted |
