ephemeral "vault_kv_secret_v2" "application3" {
  mount = var.VAULT_KV_V2_MOUNT
  name = "${var.VAULT_SECRETS_PATH}/application3"
} 

resource "aws_secretsmanager_secret_version" "application3" {
  secret_id  = "arn:aws:secretsmanager:us-east-2:386827457018:secret:application3-2TCryq"
  secret_string_wo = jsonencode(ephemeral.vault_kv_secret_v2.application3.data)
  secret_string_wo_version = var.VAULT_SECRETS_VERSION["application3"]
} 

ephemeral "vault_kv_secret_v2" "application1" {
  mount = var.VAULT_KV_V2_MOUNT
  name = "${var.VAULT_SECRETS_PATH}/application1"
} 

resource "aws_secretsmanager_secret_version" "application1" {
  secret_id  = "arn:aws:secretsmanager:us-east-2:386827457018:secret:application1-uycBtf"
  secret_string_wo = jsonencode(ephemeral.vault_kv_secret_v2.application1.data)
  secret_string_wo_version = var.VAULT_SECRETS_VERSION["application1"]
} 

ephemeral "vault_kv_secret_v2" "application2" {
  mount = var.VAULT_KV_V2_MOUNT
  name = "${var.VAULT_SECRETS_PATH}/application2"
} 

resource "aws_secretsmanager_secret_version" "application2" {
  secret_id  = "arn:aws:secretsmanager:us-east-2:386827457018:secret:application2-BTq8co"
  secret_string_wo = jsonencode(ephemeral.vault_kv_secret_v2.application2.data)
  secret_string_wo_version = var.VAULT_SECRETS_VERSION["application2"]
} 

ephemeral "vault_kv_secret_v2" "application4" {
  mount = var.VAULT_KV_V2_MOUNT
  name = "${var.VAULT_SECRETS_PATH}/application4"
} 

resource "aws_secretsmanager_secret_version" "application4" {
  secret_id  = "arn:aws:secretsmanager:us-east-2:386827457018:secret:application4-6KHkhi"
  secret_string_wo = jsonencode(ephemeral.vault_kv_secret_v2.application4.data)
  secret_string_wo_version = var.VAULT_SECRETS_VERSION["application4"]
} 

ephemeral "vault_kv_secret_v2" "application5" {
  mount = var.VAULT_KV_V2_MOUNT
  name = "${var.VAULT_SECRETS_PATH}/application5"
} 

resource "aws_secretsmanager_secret_version" "application5" {
  secret_id  = "arn:aws:secretsmanager:us-east-2:386827457018:secret:application5-WeYtMp"
  secret_string_wo = jsonencode(ephemeral.vault_kv_secret_v2.application5.data)
  secret_string_wo_version = var.VAULT_SECRETS_VERSION["application5"]
} 

