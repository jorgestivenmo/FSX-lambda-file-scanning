# FSX-lambda-file-scanning
This project contains an AWS lambda that perform a scanning files on the FSX storage service to analize them with a trend micro file scanning to check if them are infected files

## Descripción del Proyecto
Este proyecto implementa una función Lambda de AWS que realiza el análisis de amenazas en archivos almacenados en un entorno FSx SMB. La función Lambda interactúa con varios servicios de AWS para:

- Escanear archivos utilizando Ttrend Micro Vision One.
- Detectar amenazas y manejar archivos infectados.
- Eliminar archivos del FSx o enviarlos a un bucket de S3 (cuarentena).
  
La infraestructura se gestiona mediante Infrastructure as Code (IaC), utilizando AWS CloudFormation o AWS CDK para definir y desplegar todos los recursos necesarios.

### Componentes Principales
#### 1. Función Lambda
La Lambda se encarga de:

  - Acceder al FSx SMB.
  - Escanear archivos para detectar amenazas.
  - manejar archivos infectados (enviar a cuarentena o eliminar).

###### Flujo de trabajo principal de la Lambda:

```text
    Lambda ->> FSx: Accede a los archivos del FSx
    Lambda ->> VisionOne: Escanear archivo para detectar amenazas
    VisionOne ->> Lambda: Devuelve resultados del análisis
    Lambda ->> S3: Envía archivos infectados a un bucket de cuarentena (si se configura)
    Lambda ->> FSx: Elimina archivos infectados del FSx (si se configura)
```
#### 2. AWS FSx
- Almacena los archivos que se van a analizar.
- Se accede a través de SMB y se requieren credenciales seguras (almacenadas en AWS Secrets Manager).

#### 3. AWS Secrets Manager
- Almacena credenciales seguras para acceder al FSx SMB.
- Configurado como una variable de entorno de la Lambda.

#### 4. AWS S3 (Opcional - Cuarentena)
- Almacena archivos infectados si se detectan amenazas.
- Configurado mediante la variable de entorno QUARENTINE_BUCKET_NAME.

##### 5. AWS IAM
- Define los permisos necesarios para que la Lambda acceda a los servicios de AWS.
- Configurado mediante roles de IAM.

##### 6. AWS CloudFormation/AWS CDK (IaC)
  - Define y despliega toda la infraestructura necesaria:
    - Lambda.
    - FSx.
    - Bucket de S3 (cuarentena).
    - IAM Roles.
    - Políticas de seguridad.


### Requisitos Previos

#### Requisitos de Infraestructura

- Un recurso FSx configurado y accesible via SMB.
- Un bucket de S3 con políticas de IAM adecuadas (si se configura cuarentena).
- Un secreto en AWS Secrets Manager con las credenciales del FSx.

#### Requisitos para la Lambda

- Permisos IAM necesarios para:
    - Acceder al FSx.
    - Escanear archivos con Vision One.
    - Acceder al bucket de S3 (si se configura).

- Variables de entorno configuradas:
```yaml
    SECRET_FSX: "nombre_del_secreto"
    MIN: "60"  # (minutos para filtrar archivos recientes)
    QUARENTINE_BUCKET_NAME: "BucketCuarentena"
    DELETE_FILES: "true" | "false"
    MAX_SIZE_SCANNED_FILE: "100"  # (tamaño máximo en MB)
```

### Implementación con IaC
Para implementar esta solución, se utiliza AWS CloudFormation o AWS CDK. A continuación, se muestra un ejemplo de plantilla CloudFormation:

```yaml
# Plantilla CloudFormation para desplegar la Lambda y la infraestructura relacionada

Resources:

  # 1. Recurso Lambda
  FileProcessingLambda:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: FileProcessingLambda
      Runtime: python3.8
      Role: !GetAtt LambdaExecutionRole.Arn
      Handler: lambda_function.lambda_handler
      MemorySize: 512
      Timeout: 180
      Environment:
        Variables:
          SECRET_FSX: "nombre_del_secreto"
          MIN: "60"
          QUARENTINE_BUCKET_NAME: "BucketCuarentena"
          DELETE_FILES: "true"
          MAX_SIZE_SCANNED_FILE: "100"

  # 2. Rol de IAM para la Lambda
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: LambdaExecutionPolicy
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action:
                  - secretsmanager:GetSecretValue
                  - s3:*
                  - fsx:*
                  - amaas:*
                Resource: "*"

  # 3. Recurso FSx
  FileStorageFSx:
    Type: AWS::FSx::FileSystem
    Properties:
      FileSystemType: SMB
      StorageCapacity: 32
      # Configuración adicional según necesidades

  # 4. Bucket de S3 para cuarentena
  QuarantineBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: bucket-quarantine-<uuid>
      VersioningConfiguration:
        Status: Enabled
      ServerSideEncryptionConfiguration:
        Rules:
          - ApplyServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
```

### Ejecución de la Lambda
La Lambda se desencadena mediante eventos de Amazon CloudWatch Events, o se puede invocar manualmente. El flujo de trabajo principal es:

1. **Acceso al FSx:** La Lambda se conecta al FSx SMB para acceder a los archivos.
2. **Escaneo de archivos:** Utiliza Amazon Vision One (o AMAAS) para analizar archivos.
3. **Manejo de amenazas:**
    - Si un archivo es infectado, se envía a un bucket de S3 (si se configura).
    - Si se configura DELETE_FILES, el archivo se elimina del FSx.
4. **Eliminación del archivo temporal:** El archivo se elimina del directorio /tmp de la Lambda.
   
#### Manejo de Errores
La Lambda incluye dispositivos de manejo de errores para:

- Errores al acceder al FSx.
- Errores al analizar archivos.
- Errores al enviar archivos a S3.
- Excepciones generales.
#### Monitorización y Logging
- CloudWatch: Se registran métricas y logs de la Lambda.
- Resultados del análisis: Se registra el estado del análisis de amenazas.
- Manejo de errores: Se registran errores y sus detalles.

#### Mantenimiento de la Infraestructura
La infraestructura se gestiona mediante AWS CloudFormation/AWS CDK. Para realizar cambios en la infraestructura:

- Modificar la plantilla CloudFormation/CDK.
- Desplegar los cambios.
- Validar que los recursos se hayan actualizado correctamente.

### Consideraciones de Seguridad
#### 1. Credenciales del FSx
- Almacenadas en AWS Secrets Manager.
- No se exponen nunca en el código o en los logs.

#### 2. Políticas de IAM
- Configuradas con el principio de mínimos privilegios para restringir accesos solo a lo necesario.

#### 3. Encriptación de Datos
- AWS S3: Utiliza encriptación si se configura.
- FSx: Configurado con encriptación en reposo si se requiere.

### Recursos Adicionales
- Documentación de AWS Lambda: https://aws.amazon.com/lambda/
- Documentación de AWS FSx: https://aws.amazon.com/fsx/
- Documentación de AWS Secrets Manager: https://aws.amazon.com/secrets-manager/
- Documentación de AWS S3: https://aws.amazon.com/s3/

### Soporte y Comunicados
Si tienes cualquier pregunta o necesitas ayuda para implementar esta solución, no dudes en ponerte en contacto.

#### Agradecimientos
Gracias por tu interés en este proyecto. Siéntete libre de modificar o adaptar el README según tus necesidades específicas.
