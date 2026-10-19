"""AirGap Mandates on AWS eu-central-1 (CDK v2, Python). Owner: WS-E. ARCHITECTURE §4.3, §9; CONTRACTS v2 §3, §9.

One stack:
- DynamoDB (on-demand; layout = executor/store/dynamo.create_tables), S3 inbox + Object Lock anchor bucket (GOVERNANCE 1 d)
- KMS Ed25519 keys `airgap-log` (checkpointer signs) and `airgap-w1` (witness signs). Key policies name role ARNs
  directly; the account root only administers (no kms:Sign via IAM delegation).
- Lambdas (py3.12 arm64, one role each): executor-api, tools, checkpointer, witness (W1), agent.
- Regional REST API (AWS_IAM) for host / bench / portal / tools->executor; W1 `add-checkpoint` without IAM (C2SP:
  the request is authenticated by the log signature). Private REST API (AWS_IAM + aws:SourceVpce) serving only
  /tools/{name} to the agent VPC.
- Agent VPC: 1 AZ, isolated subnets, no IGW/NAT; interface endpoints bedrock-runtime + execute-api; Flow Logs (ALL).
- EventBridge Scheduler: tick every minute (Scheduler minimum; 30 s is not expressible), anchor every 5 minutes.
- W2: unmodified litewitness on a t4g.nano in its own VPC, no inbound ports (SSM port forwarding); stop when idle.
- Roles named airgap-<principal> so executor.handler.principal_from_arn maps them; agent role has explicit Denies.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_apigateway as apigw
from aws_cdk import aws_bedrock as bedrock
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_route53resolver as r53r
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_scheduler as scheduler
from constructs import Construct

ROOT = Path(__file__).resolve().parent
LAMBDA_ZIP = ROOT / "build" / "lambda.zip"
PREFIX = "airgap-"
SONNET = ["eu.anthropic.claude-sonnet-4-5-20250929-v1:0", "eu.anthropic.claude-sonnet-4-6"]
QWEN = ["qwen.qwen3-235b-a22b-2507-v1:0"]

# physical table -> (pk, sk|None, [(gsi, hash, range)])  (types: N for seq / mandate_no, else S)
TABLES: dict[str, tuple[tuple[str, str], tuple[str, str] | None, list[tuple[str, tuple[str, str], tuple[str, str]]]]] = {
    "ledger": (("tx_id", "S"), None, [("by_vendor", ("vendor_id", "S"), ("executed_at", "S"))]),
    "mandates": (("mandate_id", "S"), None, [("by_status", ("status", "S"), ("mandate_no", "N"))]),
    "audit": (("log_id", "S"), ("seq", "N"), []),
    "registry": (("vendor_id", "S"), None, []),
    "witness_state": (("origin", "S"), None, []),
    "main": (("pk", "S"), ("sk", "S"), [("gsi1", ("gsi1pk", "S"), ("gsi1sk", "S"))]),
    "portal": (("ico", "S"), ("notif_id", "S"), []),
}


def code_sha256_hex() -> str:
    """Lambda CodeSha256 is base64(sha256(zip)); the zip is uploaded as-is, so this is the deployed code hash."""
    return hashlib.sha256(LAMBDA_ZIP.read_bytes()).hexdigest() if LAMBDA_ZIP.exists() else "0" * 64


def _attr(t: str) -> ddb.AttributeType:
    return ddb.AttributeType.NUMBER if t == "N" else ddb.AttributeType.STRING


class AirgapStack(Stack):
    def __init__(self, scope: Construct, cid: str, **kw) -> None:
        super().__init__(scope, cid, **kw)
        ctx = self.node.try_get_context
        deployment_id = ctx("deployment_id") or "DEMO"
        with_w2 = str(ctx("w2") or "true").lower() == "true"

        # ------------------------------------------------------------ data
        self.tables: dict[str, ddb.Table] = {}
        for name, (pk, sk, gsis) in TABLES.items():
            t = ddb.Table(self, f"T-{name}", table_name=PREFIX + name,
                          partition_key=ddb.Attribute(name=pk[0], type=_attr(pk[1])),
                          sort_key=ddb.Attribute(name=sk[0], type=_attr(sk[1])) if sk else None,
                          billing_mode=ddb.BillingMode.PAY_PER_REQUEST, removal_policy=RemovalPolicy.DESTROY)
            for g, h, r in gsis:
                t.add_global_secondary_index(index_name=g, partition_key=ddb.Attribute(name=h[0], type=_attr(h[1])),
                                             sort_key=ddb.Attribute(name=r[0], type=_attr(r[1])))
            self.tables[name] = t

        inbox = s3.Bucket(self, "Inbox", bucket_name=f"{PREFIX}inbox-{self.account}",
                          block_public_access=s3.BlockPublicAccess.BLOCK_ALL, enforce_ssl=True,
                          encryption=s3.BucketEncryption.S3_MANAGED, removal_policy=RemovalPolicy.DESTROY,
                          auto_delete_objects=False)
        anchor = s3.Bucket(self, "Anchor", bucket_name=f"{PREFIX}log-{self.account}", versioned=True,
                           object_lock_enabled=True,
                           object_lock_default_retention=s3.ObjectLockRetention.governance(Duration.days(1)),
                           block_public_access=s3.BlockPublicAccess.BLOCK_ALL, enforce_ssl=True,
                           encryption=s3.BucketEncryption.S3_MANAGED, removal_policy=RemovalPolicy.DESTROY)

        # ------------------------------------------------------------ roles
        lam = iam.ServicePrincipal("lambda.amazonaws.com")
        basic = iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")

        def role(name: str, by: iam.IPrincipal = lam, managed: list[iam.IManagedPolicy] | None = None) -> iam.Role:
            return iam.Role(self, f"R-{name}", role_name=PREFIX + name, assumed_by=by,
                            managed_policies=managed if managed is not None else [basic])

        human = iam.AccountRootPrincipal()  # laptops (TeamAdmin SSO) assume host/auditor/... via sts:AssumeRole
        r_exec = role("executor-api")
        # assumable by operators too, so bench/e2e can play the tools λ (TeamAdmin is account admin anyway; §9 limit)
        r_tools = role("tools", iam.CompositePrincipal(lam, human), [basic])
        r_ckpt = role("checkpointer")
        r_w1 = role("witness")
        r_agent = role("agent", managed=[])  # scoped inline log + ENI statements below (no logs:* on *)
        r_host = role("host", human, [])
        r_auditor = role("auditor", human, [])
        r_ingest = role("ingest", human, [])
        r_portal = role("vendor-portal", human, [])
        r_issuer = role("issuer", human, [])
        r_relay = role("relay", iam.CompositePrincipal(human, iam.ServicePrincipal("ec2.amazonaws.com")), [])

        # ------------------------------------------------------------ KMS (Ed25519, key policy names roles)
        def ed_key(alias: str, signer: iam.Role, readers: list[iam.Role]) -> kms.Key:
            admin = iam.PolicyStatement(
                sid="AccountAdministersOnly", principals=[iam.AccountRootPrincipal()], resources=["*"],
                actions=["kms:CreateAlias", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
                         "kms:RevokeGrant", "kms:Disable*", "kms:Get*", "kms:DeleteAlias", "kms:TagResource",
                         "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"])  # no CreateGrant
            sign = iam.PolicyStatement(sid="SignerRoleOnly", principals=[iam.ArnPrincipal(signer.role_arn)],
                                       actions=["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"], resources=["*"])
            read = iam.PolicyStatement(sid="Verifiers", principals=[iam.ArnPrincipal(r.role_arn) for r in readers],
                                       actions=["kms:GetPublicKey", "kms:DescribeKey"], resources=["*"])
            return kms.Key(self, f"K-{alias}", alias=f"alias/{PREFIX}{alias}", key_spec=kms.KeySpec.ECC_NIST_EDWARDS25519,
                           key_usage=kms.KeyUsage.SIGN_VERIFY, pending_window=Duration.days(7),
                           removal_policy=RemovalPolicy.DESTROY,
                           policy=iam.PolicyDocument(statements=[admin, sign, read]))

        k_log = ed_key("log", r_ckpt, [r_exec, r_w1, r_host, r_auditor, r_relay])
        k_w1 = ed_key("w1", r_w1, [r_exec, r_ckpt, r_host, r_auditor, r_relay])

        # ------------------------------------------------------------ Guardrails (A1 input + egress 2nd opinion)
        iban_rx = r"[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,4})?"
        guard = bedrock.CfnGuardrail(
            self, "Guardrail", name=f"{PREFIX}a1",
            blocked_input_messaging="Blocked by A1 Guardrails.", blocked_outputs_messaging="Blocked by Guardrails.",
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(filters_config=[
                bedrock.CfnGuardrail.ContentFilterConfigProperty(type="PROMPT_ATTACK", input_strength="HIGH",
                                                                 output_strength="NONE")]),
            sensitive_information_policy_config=bedrock.CfnGuardrail.SensitiveInformationPolicyConfigProperty(
                regexes_config=[
                    bedrock.CfnGuardrail.RegexConfigProperty(name="IBAN", pattern=iban_rx, action="BLOCK"),
                    bedrock.CfnGuardrail.RegexConfigProperty(name="ICO", pattern=r"\b[0-9]{8}\b", action="BLOCK")]))

        # ------------------------------------------------------------ code + functions
        code = lambda_.Code.from_asset(str(LAMBDA_ZIP)) if LAMBDA_ZIP.exists() else \
            lambda_.Code.from_inline("def handler(e, c):\n    raise RuntimeError('run infra/build_lambda.sh')\n")
        base_env = {"AIRGAP_BACKEND": "aws", "AIRGAP_DEMO_PROFILE": "demo", "AIRGAP_DEPLOYMENT_ID": deployment_id,
                    "AIRGAP_TABLE_PREFIX": PREFIX, "AIRGAP_INBOX_BUCKET": inbox.bucket_name,
                    "AIRGAP_ANCHOR_BUCKET": anchor.bucket_name, "AIRGAP_KMS_KEY_ID": k_log.key_id,
                    "AIRGAP_CODE_SHA256": code_sha256_hex(), "AIRGAP_DATA_DIR": "data",
                    # only the checkpointer holds kms:Sign on the log key: no inline checkpoints anywhere else
                    # (log.checkpoint_due is also true when no checkpoint exists yet; the first tick creates one)
                    "AIRGAP_CHECKPOINT_EVERY_N_LEAVES": "1000000000", "AIRGAP_CHECKPOINT_MAX_SECONDS": "1000000000"}

        def fn(name: str, handler: str, r: iam.Role, *, env: dict[str, str] | None = None, timeout: int = 30,
               memory: int = 1024, **extra) -> lambda_.Function:
            return lambda_.Function(self, f"F-{name}", function_name=PREFIX + name, runtime=lambda_.Runtime.PYTHON_3_12,
                                    architecture=lambda_.Architecture.ARM_64, handler=handler, code=code, role=r,
                                    memory_size=memory, timeout=Duration.seconds(timeout),
                                    environment={**base_env, **(env or {})},
                                    log_retention=logs.RetentionDays.ONE_WEEK, **extra)

        if ctx("w2_vkey"):  # W2 litewitness cosigner vkey (printed by litewitness at startup; infra/w2_ctl.sh vkey)
            base_env["AIRGAP_W2_VKEY"] = ctx("w2_vkey")
        f_exec = fn("executor", "airgap_entry.handler", r_exec,
                    env={"AIRGAP_GUARDRAIL_ID": guard.attr_guardrail_id,  # egress E-GUARDRAILS 2nd opinion
                         "AIRGAP_WITNESS_KMS_KEY_ID": k_w1.key_id})  # GetPublicKey only (vkeys in /health, export)
        # AIRGAP_W1_LOG_VKEY: pinned log vkey, derived from KMS by infra/post_deploy.py and stored in cdk.context.json
        # so a later deploy keeps it (an env var set out of band would be erased by every deploy)
        w1_env = {"AIRGAP_WITNESS_KMS_KEY_ID": k_w1.key_id, "AIRGAP_KMS_KEY_ID": ""}
        if ctx("w1_log_vkey"):
            w1_env["AIRGAP_W1_LOG_VKEY"] = ctx("w1_log_vkey")
        # unauthenticated route (C2SP: the request carries its own log signature) is throttled at the API stage
        # (method_options below); no reserved concurrency: this account's pool is too small to carve a share out
        f_w1 = fn("witness", "witness.witness.lambda_handler", r_w1, env=w1_env)
        f_ckpt = fn("checkpointer", "airgap_scheduled.handler", r_ckpt, timeout=60,
                    env={"AIRGAP_CHECKPOINT_EVERY_N_LEAVES": "10", "AIRGAP_CHECKPOINT_MAX_SECONDS": "30",
                         "AIRGAP_WITNESS_KMS_KEY_ID": k_w1.key_id})

        # ------------------------------------------------------------ regional API (IAM)
        api = apigw.RestApi(self, "Api", rest_api_name=f"{PREFIX}api",
                            endpoint_configuration=apigw.EndpointConfiguration(types=[apigw.EndpointType.REGIONAL]),
                            deploy_options=apigw.StageOptions(
                                stage_name="prod", throttling_rate_limit=50, throttling_burst_limit=100,
                                method_options={"/witness/add-checkpoint/POST": apigw.MethodDeploymentOptions(
                                    throttling_rate_limit=5, throttling_burst_limit=10)}),
                            default_method_options=apigw.MethodOptions(
                                authorization_type=apigw.AuthorizationType.IAM))
        exec_int = apigw.LambdaIntegration(f_exec)
        api.root.add_method("ANY", exec_int)
        api.root.add_resource("{proxy+}").add_method("ANY", exec_int)
        w1 = api.root.add_resource("witness").add_resource("add-checkpoint")
        w1.add_method("POST", apigw.LambdaIntegration(f_w1), authorization_type=apigw.AuthorizationType.NONE)
        api_url = f"https://{api.rest_api_id}.execute-api.{self.region}.amazonaws.com/prod"  # no stage dependency

        def invoke(method: str, path: str, a: apigw.RestApi = api) -> str:
            return a.arn_for_execute_api(method, path, "prod")

        f_ckpt.add_environment("AIRGAP_WITNESS_URL", f"{api_url}/witness")  # base: the client appends /add-checkpoint
        f_exec.add_environment("AIRGAP_WITNESS_URL", f"{api_url}/witness")  # base: the client appends /add-checkpoint

        # ------------------------------------------------------------ agent VPC (no IGW, no NAT)
        vpc = ec2.Vpc(self, "AgentVpc", vpc_name=f"{PREFIX}agent", max_azs=1, nat_gateways=0,
                      ip_addresses=ec2.IpAddresses.cidr("10.77.0.0/24"),
                      subnet_configuration=[ec2.SubnetConfiguration(name="isolated", cidr_mask=26,
                                                                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED)],
                      flow_logs={"all": ec2.FlowLogOptions(
                          destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                              logs.LogGroup(self, "FlowLogs", log_group_name=f"/{PREFIX}agent/flow-logs",
                                            retention=logs.RetentionDays.ONE_WEEK,
                                            removal_policy=RemovalPolicy.DESTROY)),
                          traffic_type=ec2.FlowLogTrafficType.ALL)})
        sg_agent = ec2.SecurityGroup(self, "SgAgent", vpc=vpc, allow_all_outbound=False,
                                     description="agent lambda: HTTPS to VPC endpoints only")
        sg_vpce = ec2.SecurityGroup(self, "SgVpce", vpc=vpc, allow_all_outbound=False,
                                    description="interface endpoints: HTTPS from the agent")
        sg_vpce.add_ingress_rule(sg_agent, ec2.Port.tcp(443))
        sg_agent.add_egress_rule(sg_vpce, ec2.Port.tcp(443))
        isolated = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED)
        vpce_bedrock = vpc.add_interface_endpoint("BedrockRuntime", service=ec2.InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME,
                                                  subnets=isolated, security_groups=[sg_vpce], private_dns_enabled=True)
        vpce_api = vpc.add_interface_endpoint("ExecuteApi", service=ec2.InterfaceVpcEndpointAwsService.APIGATEWAY,
                                              subnets=isolated, security_groups=[sg_vpce], private_dns_enabled=True)
        # Endpoint policies: without them the endpoints carry ANY principal to ANY API/model, e.g. a private API in an
        # attacker's account (execute-api) or Bedrock with the attacker's own keys (bedrock-runtime) = exfiltration.
        acct_only = {"StringEquals": {"aws:PrincipalAccount": self.account}}
        vpce_api.add_to_policy(iam.PolicyStatement(
            principals=[iam.AnyPrincipal()], actions=["execute-api:Invoke"], conditions=acct_only,
            resources=[f"arn:aws:execute-api:{self.region}:{self.account}:*/prod/POST/tools/*"]))
        vpce_bedrock.add_to_policy(iam.PolicyStatement(
            principals=[iam.AnyPrincipal()], conditions=acct_only, resources=["*"],
            actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:Converse",
                     "bedrock:ConverseStream", "bedrock:ApplyGuardrail"]))
        # DNS: the VPC resolver answers public names even without IGW/NAT, and security groups / Flow Logs do not see
        # it (DNS tunnelling). DNS Firewall: only the two endpoint names resolve, everything else gets NXDOMAIN.
        allow_dns = r53r.CfnFirewallDomainList(self, "DnsAllow", name=f"{PREFIX}agent-allow", domains=[
            f"bedrock-runtime.{self.region}.amazonaws.com.", f"*.execute-api.{self.region}.amazonaws.com."])
        block_dns = r53r.CfnFirewallDomainList(self, "DnsBlockAll", name=f"{PREFIX}agent-block-all", domains=["*"])
        fw = r53r.CfnFirewallRuleGroup(self, "DnsFirewall", name=f"{PREFIX}agent-dns", firewall_rules=[
            r53r.CfnFirewallRuleGroup.FirewallRuleProperty(
                priority=100, action="ALLOW", firewall_domain_list_id=allow_dns.attr_id),
            r53r.CfnFirewallRuleGroup.FirewallRuleProperty(
                priority=200, action="BLOCK", block_response="NXDOMAIN", firewall_domain_list_id=block_dns.attr_id)])
        r53r.CfnFirewallRuleGroupAssociation(self, "DnsFirewallAssoc", firewall_rule_group_id=fw.attr_id,
                                             vpc_id=vpc.vpc_id, priority=101, name=f"{PREFIX}agent-dns")
        dns_logs = logs.LogGroup(self, "DnsQueryLogs", log_group_name=f"/{PREFIX}agent/dns-queries",
                                 retention=logs.RetentionDays.ONE_WEEK, removal_policy=RemovalPolicy.DESTROY)
        qlog = r53r.CfnResolverQueryLoggingConfig(self, "DnsQueryLogging", name=f"{PREFIX}agent-dns",
                                                  destination_arn=dns_logs.log_group_arn)
        r53r.CfnResolverQueryLoggingConfigAssociation(self, "DnsQueryLoggingAssoc",
                                                      resolver_query_log_config_id=qlog.attr_id, resource_id=vpc.vpc_id)

        # ------------------------------------------------------------ private API: /tools/{name} for the agent
        f_tools = fn("tools", "airgap_entry.handler", r_tools,
                     env={"AIRGAP_EXECUTOR_URL": api_url, "AIRGAP_GATEWAY": "local"})
        papi = apigw.RestApi(
            self, "AgentApi", rest_api_name=f"{PREFIX}agent-api",
            endpoint_configuration=apigw.EndpointConfiguration(types=[apigw.EndpointType.PRIVATE],
                                                               vpc_endpoints=[vpce_api]),
            deploy_options=apigw.StageOptions(stage_name="prod", throttling_rate_limit=20, throttling_burst_limit=40),
            default_method_options=apigw.MethodOptions(authorization_type=apigw.AuthorizationType.IAM),
            policy=iam.PolicyDocument(statements=[
                iam.PolicyStatement(principals=[iam.ArnPrincipal(r_agent.role_arn)], actions=["execute-api:Invoke"],
                                    resources=["execute-api:/*/POST/tools/*"]),
                iam.PolicyStatement(effect=iam.Effect.DENY, principals=[iam.AnyPrincipal()],
                                    actions=["execute-api:Invoke"], resources=["execute-api:/*"],
                                    conditions={"StringNotEquals": {"aws:SourceVpce": vpce_api.vpc_endpoint_id}})]))
        papi.root.add_resource("tools").add_resource("{name}").add_method("POST", apigw.LambdaIntegration(f_tools))
        tools_url = f"https://{papi.rest_api_id}.execute-api.{self.region}.amazonaws.com/prod"

        f_agent = fn("agent", "agent.lambda_handler.handler", r_agent, timeout=300, memory=512,
                     env={"AIRGAP_TOOLS_URL": tools_url, "AGENT_MODE": "quarantined", "AIRGAP_SONNET_BUDGET": "20",
                          "AIRGAP_GUARDRAIL_ID": guard.attr_guardrail_id},
                     vpc=vpc, vpc_subnets=isolated, security_groups=[sg_agent])

        # ------------------------------------------------------------ grants
        t = self.tables
        for name in ("ledger", "mandates", "audit", "registry", "main"):
            t[name].grant_read_write_data(r_exec)
        inbox.grant_read(r_exec)
        # tools λ: writes its tool_call leaves + toollog rows itself; reads the registry for Cedar context
        def main_rw(r: iam.Role, prefixes: list[str]) -> None:
            """RW on `main` limited to items whose pk starts with one of `prefixes` (dynamodb:LeadingKeys)."""
            r.add_to_policy(iam.PolicyStatement(
                actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query",
                         "dynamodb:ConditionCheckItem", "dynamodb:DescribeTable"],
                resources=[t["main"].table_arn, t["main"].table_arn + "/index/*"],
                conditions={"ForAllValues:StringLike": {"dynamodb:LeadingKeys": [p + "#*" for p in prefixes]}}))

        t["audit"].grant_read_write_data(r_tools)
        main_rw(r_tools, ["toolsession", "counter"])  # toollog rows + tool rate counters only
        # every leaf append asks checkpoint.latest() whether a checkpoint is due: read-only on checkpoint rows
        r_tools.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:GetItem", "dynamodb:Query"], resources=[t["main"].table_arn],
            conditions={"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["checkpoint#*"]}}))
        t["registry"].grant_read_data(r_tools)
        r_tools.add_to_policy(iam.PolicyStatement(actions=["execute-api:Invoke"], resources=[
            invoke("POST", "/proposals"), invoke("POST", "/changes"), invoke("POST", "/egress"),
            invoke("GET", "/vendors"), invoke("GET", "/vendors/*"), invoke("GET", "/inbox"), invoke("GET", "/inbox/*"),
            invoke("GET", "/mandates/active")]))
        # checkpointer: log key (key policy), audit/main read+write (checkpoints), anchor bucket put
        t["audit"].grant_read_write_data(r_ckpt)
        main_rw(r_ckpt, ["checkpoint"])
        anchor.grant_put(r_ckpt)
        anchor.grant_read(r_auditor)
        t["witness_state"].grant_read_write_data(r_w1)
        # humans
        r_host.add_to_policy(iam.PolicyStatement(actions=["execute-api:Invoke"], resources=[
            invoke("*", "/mandates*"), invoke("GET", "/proposals*"), invoke("GET", "/changes*"),
            invoke("POST", "/changes/*/reject"), invoke("GET", "/challenges/*"), invoke("POST", "/signatures"),
            invoke("GET", "/inbox*"), invoke("GET", "/vendors*"), invoke("GET", "/ledger"), invoke("GET", "/receipts/*"),
            invoke("GET", "/checkpoint"), invoke("GET", "/audit/export"), invoke("GET", "/export/pain001/*"),
            invoke("GET", "/health"), invoke("GET", "/attestations/*")]))
        r_auditor.add_to_policy(iam.PolicyStatement(actions=["execute-api:Invoke"], resources=[
            invoke("GET", "/*")]))
        r_ingest.add_to_policy(iam.PolicyStatement(actions=["execute-api:Invoke"], resources=[invoke("POST", "/ingest")]))
        inbox.grant_put(r_ingest)
        r_portal.add_to_policy(iam.PolicyStatement(actions=["execute-api:Invoke"], resources=[
            invoke("POST", "/callbacks/*"), invoke("POST", "/changes/*"), invoke("POST", "/attestations"),
            invoke("GET", "/challenges/*"), invoke("POST", "/signatures"), invoke("GET", "/changes*")]))
        t["portal"].grant_read_write_data(r_portal)
        t["portal"].grant_read_write_data(r_exec)  # executor writes portal notifications (callback codes)
        r_issuer.add_to_policy(iam.PolicyStatement(actions=["execute-api:Invoke"], resources=[
            invoke("POST", "/changes/*/attestations")]))
        r_relay.add_to_policy(iam.PolicyStatement(actions=["execute-api:Invoke"], resources=[
            invoke("GET", "/checkpoint"), invoke("GET", "/audit/export"), invoke("POST", "/checkpoint/cosignature")]))

        # agent: own log group only, ENI management for the VPC attachment
        r_agent.add_to_policy(iam.PolicyStatement(actions=["logs:CreateLogStream", "logs:PutLogEvents"], resources=[
            f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/{PREFIX}agent:*"]))
        r_agent.add_to_policy(iam.PolicyStatement(resources=["*"], actions=[
            "ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DeleteNetworkInterface",
            "ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses"]))
        # agent: model invocation + private /tools/* only; explicit Denies (S7)
        r_agent.add_to_policy(iam.PolicyStatement(actions=["bedrock:InvokeModel", "bedrock:Converse"], resources=[
            *[f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/{m}" for m in SONNET],
            "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0",
            "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-6",
            *[f"arn:aws:bedrock:{self.region}::foundation-model/{m}" for m in QWEN]]))
        for r in (r_agent, r_exec):
            r.add_to_policy(iam.PolicyStatement(actions=["bedrock:ApplyGuardrail"], resources=[guard.attr_guardrail_arn]))
        r_agent.add_to_policy(iam.PolicyStatement(actions=["execute-api:Invoke"],
                                                  resources=[invoke("POST", "/tools/*", papi)]))
        deny = iam.Effect.DENY
        r_agent.add_to_policy(iam.PolicyStatement(sid="DenyState", effect=deny, actions=[
            "dynamodb:*", "kms:Sign", "kms:GenerateDataKey*", "secretsmanager:*", "states:*", "s3:Put*", "s3:Delete*",
            "lambda:InvokeFunction", "iam:*", "sts:AssumeRole"], resources=["*"]))
        # kms:* on our keys; kms:Decrypt elsewhere stays possible because Lambda decrypts the function's own env
        # vars (aws/lambda key) with the execution role
        r_agent.add_to_policy(iam.PolicyStatement(sid="DenyOurKeys", effect=deny, actions=["kms:*"],
                                                  resources=[k_log.key_arn, k_w1.key_arn]))
        # stolen agent credentials are useless outside the agent VPC (aws:SourceVpc is set only via its endpoints)
        r_agent.add_to_policy(iam.PolicyStatement(sid="DenyOutsideAgentVpc", effect=deny, resources=["*"],
                                                  actions=["bedrock:*", "execute-api:Invoke"],
                                                  conditions={"StringNotEquals": {"aws:SourceVpc": vpc.vpc_id}}))
        r_agent.add_to_policy(iam.PolicyStatement(sid="DenyMoneyRoutes", effect=deny, actions=["execute-api:Invoke"],
                                                  resources=[invoke("*", "/signatures"), invoke("*", "/mandates*"),
                                                             invoke("*", "/changes/*/approve"), invoke("*", "/proposals"),
                                                             invoke("*", "/changes"), invoke("*", "/egress")]))
        executor_tables = [t[n].table_arn for n in ("ledger", "mandates", "audit", "registry", "witness_state", "main")]
        for r in (r_host, r_auditor, r_ingest, r_issuer, r_relay):
            r.add_to_policy(iam.PolicyStatement(effect=deny, actions=["dynamodb:*", "kms:Sign", "secretsmanager:*"],
                                                resources=["*"]))
        r_portal.add_to_policy(iam.PolicyStatement(effect=deny, actions=["dynamodb:*"],
                                                   resources=executor_tables + [a + "/index/*" for a in executor_tables]))
        r_portal.add_to_policy(iam.PolicyStatement(effect=deny, actions=["kms:Sign", "secretsmanager:*"],
                                                   resources=["*"]))

        # ------------------------------------------------------------ scheduler
        r_sched = iam.Role(self, "R-scheduler", role_name=f"{PREFIX}scheduler",
                           assumed_by=iam.ServicePrincipal("scheduler.amazonaws.com"))
        f_ckpt.grant_invoke(r_sched)
        for sid, expr, action in (("Tick", "rate(1 minute)", "tick"), ("Anchor", "rate(5 minutes)", "anchor")):
            scheduler.CfnSchedule(self, f"S-{sid}", name=f"{PREFIX}{action}", schedule_expression=expr,
                                  flexible_time_window=scheduler.CfnSchedule.FlexibleTimeWindowProperty(mode="OFF"),
                                  target=scheduler.CfnSchedule.TargetProperty(
                                      arn=f_ckpt.function_arn, role_arn=r_sched.role_arn,
                                      input=f'{{"action": "{action}", "log_id": "audit"}}'))

        # ------------------------------------------------------------ W2 litewitness (optional)
        if with_w2:
            w2_vpc = ec2.Vpc(self, "W2Vpc", vpc_name=f"{PREFIX}w2", max_azs=1, nat_gateways=0,
                             ip_addresses=ec2.IpAddresses.cidr("10.78.0.0/26"),
                             subnet_configuration=[ec2.SubnetConfiguration(name="public", cidr_mask=28,
                                                                           subnet_type=ec2.SubnetType.PUBLIC)])
            sg_w2 = ec2.SecurityGroup(self, "SgW2", vpc=w2_vpc, allow_all_outbound=True,
                                      description="W2: no inbound; SSM port forwarding only")
            r_w2 = role("w2-instance", iam.ServicePrincipal("ec2.amazonaws.com"),
                        [iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")])
            user_data = ec2.UserData.for_linux()
            user_data.add_commands((ROOT / "w2_userdata.sh").read_text())
            w2 = ec2.Instance(self, "W2", instance_name=f"{PREFIX}w2", vpc=w2_vpc, security_group=sg_w2,
                              instance_type=ec2.InstanceType("t4g.nano"), role=r_w2, user_data=user_data,
                              machine_image=ec2.MachineImage.latest_amazon_linux2023(
                                  cpu_type=ec2.AmazonLinuxCpuType.ARM_64),
                              vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
                              require_imdsv2=True)
            CfnOutput(self, "W2InstanceId", value=w2.instance_id)
            # every tick relays new checkpoints to W2 over SSM RunCommand (witness.relay_w2.after_tick). No reserved
            # concurrency 1: this account's whole pool is 10 and AWS keeps 10 unreserved; an overlapping tick is
            # harmless (W2 answers 409 with its size, the relay retries / catches up next tick).
            f_ckpt.add_environment("AIRGAP_W2_INSTANCE_ID", w2.instance_id)
            r_ckpt.add_to_policy(iam.PolicyStatement(actions=["ssm:SendCommand"], resources=[
                f"arn:aws:ec2:{self.region}:{self.account}:instance/{w2.instance_id}",
                f"arn:aws:ssm:{self.region}::document/AWS-RunShellScript"]))
            r_ckpt.add_to_policy(iam.PolicyStatement(actions=["ssm:GetCommandInvocation"], resources=["*"]))

        # ------------------------------------------------------------ outputs
        for k, v in {"ApiUrl": api_url, "AgentToolsUrl": tools_url, "LogKeyId": k_log.key_id, "W1KeyId": k_w1.key_id,
                     "InboxBucket": inbox.bucket_name, "AnchorBucket": anchor.bucket_name,
                     "AgentRoleArn": r_agent.role_arn, "HostRoleArn": r_host.role_arn,
                     "ToolsRoleArn": r_tools.role_arn, "AgentFunction": f_agent.function_name,
                     "VpceBedrock": vpce_bedrock.vpc_endpoint_id, "VpceExecuteApi": vpce_api.vpc_endpoint_id,
                     "CodeSha256": code_sha256_hex(), "CodeSha256B64": base64.b64encode(
                         bytes.fromhex(code_sha256_hex())).decode()}.items():
            CfnOutput(self, k, value=v)
