################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../component/lists/fsl_component_generic_list.c 

OBJS += \
./component/lists/fsl_component_generic_list.o 

C_DEPS += \
./component/lists/fsl_component_generic_list.d 


# Each subdirectory must supply rules for building sources it contributes
component/lists/%.o: ../component/lists/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK66FN2M0VMD18 -DCPU_MK66FN2M0VMD18_cm4 -DUSE_RTOS=1 -DPRINTF_ADVANCED_ENABLE=1 -DFRDM_K66F -DFREEDOM -DLWIP_DISABLE_PBUF_POOL_SIZE_SANITY_CHECKS=1 -DSERIAL_PORT_TYPE_UART=1 -DSDK_OS_FREE_RTOS -DMCUXPRESSO_SDK -DSDK_DEBUGCONSOLE=0 -DCR_INTEGER_PRINTF -DPRINTF_FLOAT_ENABLE=0 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -I"D:\ProyectosRedes\P1_Ethernet_Client\board" -I"D:\ProyectosRedes\P1_Ethernet_Client\source" -I"D:\ProyectosRedes\P1_Ethernet_Client\mdio" -I"D:\ProyectosRedes\P1_Ethernet_Client\phy" -I"D:\ProyectosRedes\P1_Ethernet_Client\lwip\contrib\apps\tcpecho" -I"D:\ProyectosRedes\P1_Ethernet_Client\lwip\port" -I"D:\ProyectosRedes\P1_Ethernet_Client\lwip\src" -I"D:\ProyectosRedes\P1_Ethernet_Client\lwip\src\include" -I"D:\ProyectosRedes\P1_Ethernet_Client\drivers" -I"D:\ProyectosRedes\P1_Ethernet_Client\utilities" -I"D:\ProyectosRedes\P1_Ethernet_Client\device" -I"D:\ProyectosRedes\P1_Ethernet_Client\component\uart" -I"D:\ProyectosRedes\P1_Ethernet_Client\component\serial_manager" -I"D:\ProyectosRedes\P1_Ethernet_Client\component\lists" -I"D:\ProyectosRedes\P1_Ethernet_Client\CMSIS" -I"D:\ProyectosRedes\P1_Ethernet_Client\freertos\freertos_kernel\include" -I"D:\ProyectosRedes\P1_Ethernet_Client\freertos\freertos_kernel\portable\GCC\ARM_CM4F" -O0 -fno-common -g3 -c -ffunction-sections -fdata-sections -ffreestanding -fno-builtin -fmerge-constants -fmacro-prefix-map="../$(@D)/"=. -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


