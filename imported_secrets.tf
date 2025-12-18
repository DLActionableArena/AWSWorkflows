import {
  to = aws_secretsmanager_secret_version.application3
  identity = {
    secret_id  = "arn:aws:secretsmanager:us-east-2:386827457018:secret:application3-2TCryq"
    version_id = "terraform-20251218150957719600000003"
  }
}

import {
  to = aws_secretsmanager_secret_version.application1
  identity = {
    secret_id  = "arn:aws:secretsmanager:us-east-2:386827457018:secret:application1-uycBtf"
    version_id = "terraform-20251218150957719600000002"
  }
}

import {
  to = aws_secretsmanager_secret_version.application2
  identity = {
    secret_id  = "arn:aws:secretsmanager:us-east-2:386827457018:secret:application2-BTq8co"
    version_id = "terraform-20251218150957719600000004"
  }
}

import {
  to = aws_secretsmanager_secret_version.application4
  identity = {
    secret_id  = "arn:aws:secretsmanager:us-east-2:386827457018:secret:application4-6KHkhi"
    version_id = "terraform-20251218151429464200000001"
  }
}

import {
  to = aws_secretsmanager_secret_version.application5
  identity = {
    secret_id  = "arn:aws:secretsmanager:us-east-2:386827457018:secret:application5-WeYtMp"
    version_id = "terraform-20251218152343871200000002"
  }
}

