# LDAP

Various tools to manipulate LDAP servers in XWiki.

* Project Lead: [Thomas Mortagne](http://www.xwiki.org/xwiki/bin/view/XWiki/ThomasMortagne)
* [Documentation & Downloads](http://extensions.xwiki.org/xwiki/bin/view/Extension/LDAP/)
* [Issue Tracker](http://jira.xwiki.org/browse/LDAP)
* Communication: [Mailing List](http://dev.xwiki.org/xwiki/bin/view/Community/MailingLists), [IRC](http://dev.xwiki.org/xwiki/bin/view/Community/IRC)
* [Development Practices](http://dev.xwiki.org)
* Minimal XWiki version supported: XWiki 8.4
* License: LGPL 2.1
* Translations: https://l10n.xwiki.org/projects/xwiki-contrib/ldap-application/
* Sonar Dashboard: N/A
* Continuous Integration Status: [![Build Status](http://ci.xwiki.org/job/XWiki%20Contrib/job/ldap/job/master/badge/icon)](http://ci.xwiki.org/job/XWiki%20Contrib/job/ldap/job/master/)

# Release

* Release

```
mvn release:prepare -Pintegration-tests,legacy
mvn release:perform -Pintegration-tests,legacy
```

* Update http://extensions.xwiki.org/xwiki/bin/view/Extension/LDAP/#HReleaseNotes
