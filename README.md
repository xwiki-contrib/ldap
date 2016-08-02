# LDAP

Various tools to manipulate LDAP servers in XWiki.

* Project Lead: [Thomas Mortagne](http://www.xwiki.org/xwiki/bin/view/XWiki/ThomasMortagne)
* [Documentation & Downloads](http://extensions.xwiki.org/xwiki/bin/view/Extension/LDAP/)
* [Issue Tracker](http://jira.xwiki.org/browse/LDAP)
* Communication: [Mailing List](http://dev.xwiki.org/xwiki/bin/view/Community/MailingLists), [IRC](http://dev.xwiki.org/xwiki/bin/view/Community/IRC)
* [Development Practices](http://dev.xwiki.org)
* Minimal XWiki version supported: XWiki 7.4
* License: LGPL 2.1
* Translations: N/A
* Sonar Dashboard: N/A
* Continuous Integration Status: [![Build Status](http://ci.xwiki.org/buildStatus/icon?job=Contrib%20-%20LDAP)](http://ci.xwiki.org/job/Contrib%20-%20LDAP/)

# Release

    mvn release:prepare -Pintegration-tests,legacy
    mvn release:perform -Pintegration-tests,legacy -Darguments="-Pintegration-tests,legacy -DskipTests"

