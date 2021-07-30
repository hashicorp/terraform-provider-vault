variable "approle_name" {
  type        = string
  description = "Name for the AppRole"
}

variable "role_id" {
  type        = string
  description = "Custom role_id, can be any string"
  default     = null
}

variable "policies" {
  type        = list(string)
  description = "List of policy names to apply to the role"
  default     = []
}
