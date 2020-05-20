package worker

import (
	"github.com/beevik/etree"
)

//Plugins is a list of xml elements that are parsed
//this and tokens logic based on https://github.com/bstapes/jenkins-decrypt/blob/master/decrypt.py
var Plugins = []string{
	"com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl",
	"com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey",
	"com.cloudbees.plugins.credentials.SystemCredentialsProvider",
	"com.michelin.cio.hudson.plugins.maskpasswords.MaskPasswordsBuildWrapper/varPasswordPairs/varPasswordPair[@password]",
	"com.michelin.plugins.plaincredentials.impl/varPasswordPairs/varPasswordPair[@password]",

	"hudson.security.HudsonPrivateSecurityRealm_-Details",
	"hudson.scm.CVSSCM.xml",
	"hudson.tools.JDKInstaller.xml",
	"scm[@class='hudson.plugins.perforce.PerforceSCM']",

	"jenkins.security.ApiTokenProperty",
	"jenkins.security.plugins.ldap.LDAPConfiguration",

	"org.jenkinsci.main.modules.cli.auth.ssh.UserPropertyImpl",
	"org.jenkinsci.plugins.GithubSecurityRealm",
	"org.jenkinsci.plugins.GithubAuthorizationStrategy",
	"org.jenkinsci.plugins.googlelogin.GoogleOAuth2SecurityRealm",
	"org.jenkinsci.plugins.p4.credentials.P4PasswordImpl",
	"org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl",
	"org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl",
}

func getmichelinattrs(n *etree.Element) (string, string) {
	var michelinvar string
	michelinpwd := n.SelectAttrValue("password", "")
	if michelinpwd != "" {
		michelinvar = n.SelectAttrValue("var", "")
	}

	return michelinvar, michelinpwd
}

func gettokensfromnode(node *etree.Element) map[string]string {
	nodeinfo := make(map[string]string)

	michelinvar, michelinpwd := getmichelinattrs(node)
	nodeinfo[michelinvar] = michelinpwd

	nodeinfo[node.Tag] = node.Text()
	for _, child := range node.ChildElements() {
		nodeinfo[child.Tag] = child.Text()

		for _, subchild := range child.ChildElements() {
			nodeinfo[subchild.Tag] = subchild.Text()

			for _, grandchild := range child.ChildElements() {
				nodeinfo[grandchild.Tag] = grandchild.Text()
			}
		}
	}
	return nodeinfo
}
