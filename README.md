# TaskManagerLoader

Negrin, esse projeto é demonstração de técnicas ADVANCED de C# e Windows internals. Coisa pikaaa mesmo.

## O que é

Injetor de shellcode que usa a técnica Hell's Gate pra chamar syscalls direto do kernel, sem passar por API convencional. Injeta shellcode customizado em processos rodando (Discord, Notepad, etc).

Usa essas técnicas:

- **Hell's Gate** - Extrai syscalls do ntdll sem deixar pistas óbvias
- **Indirect Syscalls** - Chama funções do kernel via delegate
- **Thread Hijacking** - Pega uma thread rodando e redireciona pro seu código
- **Memory Manipulation** - Escreve na memória de outro processo

## Estrutura

## Estrutura

```
├── HellGate.cs              # Hell's Gate (syscall extraction)
├── NativeStructs.cs         # Structs do Windows
├── NtSyscalls.cs            # Syscalls diretas
├── StealthInjection.cs      # A injeção em si
├── StealthUtils.cs          # Funções auxiliares
├── TaskManagerLoader.cs     # Main
└── TaskManagerLoader.csproj # Config do projeto
```

## Como Funciona

1. Inicializa as syscalls usando Hell's Gate
2. Carrega o shellcode de um arquivo binário
3. Encontra o processo alvo (Discord por padrão)
4. Aloca memória no processo
5. Escreve o shellcode na memória
6. Muda a proteção pra PAGE_EXECUTE_READ
7. Suspende uma thread do processo
8. Modifica o contexto da thread (RIP - instruction pointer)
9. Retoma a thread que executa o shellcode

## Técnicas Usadas

### Hell's Gate
Extrai a tabela de syscalls do ntdll usando hashing (djb2) pra encontrar funções por hash. Isso evita que tools de monitoring vejam chamadas óbvias.

### Indirect Syscalls
Em vez de usar OpenProcess(), AllocateVirtualMemory() etc, chama as funções NT via delegates, pegando o endereço direto:
- NtOpenProcess
- NtAllocateVirtualMemory
- NtWriteVirtualMemory
- NtProtectVirtualMemory
- NtSuspendThread/NtResumeThread
- NtGetContextThread/NtSetContextThread

Pega o endereço e chama via Marshal.GetDelegateForFunctionPointer. Mais furtivo que usar as APIs normais.

### Thread Hijacking
Suspende uma thread legítima e redireciona o fluxo modificando o RIP pra apontar pro shellcode.

## Compilação

Com dotnet:
```powershell
dotnet build -c Release
dotnet publish -c Release
```

Com MSBuild (Framework antigo):
```powershell
msbuild TaskManagerLoader.csproj /p:Configuration=Release
```

## Como Usar


```powershell
dotnet build -c Release
cd bin/Release/net6.0
./TaskManagerLoader.exe
```

Precisa de:
1. Admin rights
2. Arquivo TaskManagerLoader.shellcode.bin no diretório
3. Processo alvo (Discord) rodando

## O Shellcode

O shellcode é armazenado em TaskManagerLoader.shellcode.bin. Exemplo com msfvenom:

```bash
msfvenom -p windows/x64/messagebox -f bin -o shellcode.bin TEXT="Pwned!" TITLE="Negrin"
```

## Detalhes Técnicos

### CONTEXT64
Define o estado da thread (registradores, flags). Principais pra injeção:
- Rip - Instruction Pointer
- Rsp - Stack Pointer
- Rax, Rbx, Rcx, etc - General Purpose Registers

### OBJECT_ATTRIBUTES
Estrutura pra descrever um objeto do Windows (processo, thread, arquivo).

### Chamada de Syscall
```csharp
IntPtr funcAddr = vxTable.NtOpenProcess.pAddress;
NtOpenProcessDelegate ntOpenProcess = 
    (NtOpenProcessDelegate)Marshal.GetDelegateForFunctionPointer(funcAddr, typeof(NtOpenProcessDelegate));
int status = ntOpenProcess(pHandle, desiredAccess, pOa, pCid);
```

## Mitigações

Este código evita algumas proteções usando syscalls indiretas e Hell's Gate, mas antivírus moderno ainda pega por:
- Comportamento suspeito
- Detecção heurística
- Análise de comportamento em tempo real

## Melhorias Possíveis

- Usar janela decoy
- Tartarus's Gate (ainda mais furtivo)
- Suporte x86 (32-bit)
- Ofuscação de código C#



## Disclaimer

Feito com C# e Odio
