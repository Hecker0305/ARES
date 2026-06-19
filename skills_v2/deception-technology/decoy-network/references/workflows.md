# Decoy Network Deployment Workflow

## Architecture Design
1. Map production network topology (VLANs, subnets, routing)
2. Design duplicate decoy topology with slight variations
3. Use separate hypervisor host isolated from production
4. Route all decoy traffic through monitoring sensor

## Decoy System Build
1. Deploy Windows Server with AD, DNS, DHCP
2. Deploy Linux servers (web, app, db, file)
3. Deploy workstations with simulated user activity
4. Install common enterprise tools and agents

## Decoy Traffic Generation
1. Create Python scripts for simulated user behavior
2. Generate browsing, email, file access, and auth traffic
3. Mimic business-specific workflows (ERP, CRM, Finance)
4. Use cron schedules to simulate time-of-day patterns

## Security Monitoring
1. Deploy Zeek on decoy network TAP/SPAN
2. Forward all logs to separate SIEM index
3. Create alerts for ANY decoy network interaction
4. Never whitelist production IPs on decoy monitoring
