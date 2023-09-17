import boto3

def lambda_handler(event, context):
    # Define your EC2 parameters
    instance_name = "my-server"
    instance_type = "t2.micro"
    ami_id = "ami-0ccabb5f82d4c9af5"  # Replace with your desired AMI ID
    key_name = "widows-east-1-key"    # Replace with your key pair name
    security_group_ids = ["aws_security_group.demo-vpc-sg.id"]  # Replace with your security group IDs
    subnet_id = "aws_subnet.demo_subnet-1"  # Replace with your subnet ID

    # Create an EC2 client
    ec2 = boto3.client('ec2')

    # Launch EC2 instance
    response = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        KeyName=key_name,
        SecurityGroupIds=security_group_ids,
        SubnetId=subnet_id,
        MinCount=1,
        MaxCount=1
    )

    # Extract the instance ID of the newly created EC2 instance
    instance_id = response['Instances'][0]['InstanceId']

    # Add tags to the instance to set the name
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {
                'Key': 'Name',
                'Value': instance_name
            }
        ]
    )

    return {
        'statusCode': 200,
        'body': f'EC2 instance named "{instance_name}" with ID {instance_id} created successfully.'
    }

