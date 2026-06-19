package bloodhound

import "fmt"

func QueryFindAllDomainAdmins() (string, error) {
	return Neo4jRunQuery(`MATCH p=(g:Group)-[:MemberOf*1..]->(:Group {name:'DOMAIN ADMINS@'}) RETURN p`)
}

func QueryFindKerberoastable() (string, error) {
	return Neo4jRunQuery(`MATCH (u:User {hasspn:true}) RETURN u.name`)
}

func QueryFindASREPRoastable() (string, error) {
	return Neo4jRunQuery(`MATCH (u:User {dontreqpreauth:true}) RETURN u.name`)
}

func QueryFindDCSyncTargets() (string, error) {
	return Neo4jRunQuery(`MATCH (u:User)-[:DCSync]->(d:Domain) RETURN u.name`)
}

func QueryFindShortestPathToDA(userName string) (string, error) {
	return Neo4jRunQuery(fmt.Sprintf(`MATCH (n {name:'%s'}), (m:Group {name:'DOMAIN ADMINS@'}) WITH n,m MATCH p=shortestPath((n)-[:MemberOf|AdminTo|HasSession|ForceChangePassword|AddMember|GenericAll|GenericWrite|WriteOwner|WriteDACL|Owns|Contains|GpLink|AddKeyCredentialLink|ExecuteDCOM|AllowedToDelegate|TrustedBy|AddAllowedToAct|AllowedToAct|SQLAdmin|CanRDP|CanPSRemote*1..]->(m)) RETURN p`, userName))
}

func QueryFindUnconstrainedDelegation() (string, error) {
	return Neo4jRunQuery(`MATCH (c:Computer)-[:MemberOf*1..]->(g:Group) WHERE c.unconstraineddelegation=true RETURN c.name`)
}

func QueryFindConstrainedDelegation() (string, error) {
	return Neo4jRunQuery(`MATCH (c:Computer) WHERE c.constraineddelegation=true RETURN c.name`)
}

func QueryFindRBCD(targetComputer string) (string, error) {
	return Neo4jRunQuery(fmt.Sprintf(`MATCH (c:Computer {name:'%s'}) MATCH (u1:User)-[:AddAllowedToAct]->(u2:User) WHERE (u2)-[:AllowedToAct]->(c) OR (u2)-[:AllowedToAct*1..]->(c) RETURN u1.name, u2.name, c.name`, targetComputer))
}

func QueryFindGPODelegation() (string, error) {
	return Neo4jRunQuery(`MATCH (u:User)-[:GenericAll|WriteDACL|WriteOwner|GenericWrite]->(g:GPO) MATCH (g)-[:GpLink]->(o:OrganizationalUnit) RETURN u.name, g.name, o.name`)
}

func QueryFindSessions(userName string) (string, error) {
	return Neo4jRunQuery(fmt.Sprintf(`MATCH (c:Computer)-[:HasSession]->(u:User {name:'%s'}) RETURN c.name`, userName))
}

func QueryFindAdminRights(computerName string) (string, error) {
	return Neo4jRunQuery(fmt.Sprintf(`MATCH (u:User)-[:AdminTo]->(c:Computer {name:'%s'}) RETURN u.name`, computerName))
}

func QueryFindAllPaths() (string, error) {
	return Neo4jRunQuery(`MATCH p=shortestPath((n)-[:MemberOf|AdminTo|HasSession|ForceChangePassword|AddMember|GenericAll|GenericWrite|WriteOwner|WriteDACL|Owns|Contains|GpLink|AddKeyCredentialLink|ExecuteDCOM|AllowedToDelegate|TrustedBy|AddAllowedToAct|AllowedToAct|SQLAdmin|CanRDP|CanPSRemote]->(m:Group {name:'DOMAIN ADMINS@'})) RETURN p`)
}

func QueryFindHighValueTargets() (string, error) {
	return Neo4jRunQuery(`MATCH (u:User)-[:HasSession]->(c:Computer) WITH u, count(c) as sessions WHERE sessions > 0 OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name =~ '(?i)DOMAIN ADMINS|ENTERPRISE ADMINS|DOMAIN CONTROLLERS|ACCOUNT OPERATORS|BACKUP OPERATORS|PRINT OPERATORS|SERVER OPERATORS|ADMINISTRATORS|SYSTEM|SCHEMA ADMINS' RETURN u.name, labels(u), sessions, collect(g.name) as groups`)
}
