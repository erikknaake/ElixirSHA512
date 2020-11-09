# Learning Elixir

## Setup

(On Manjaro linux minimal)

`yaourt -S elixir`

## Compile

`mix compile`

## Run in REPL

`iex -S mix`

Call function you want e.g.:

`ElixirSha512.hello`

Recompile with `recompile()` or exit and run `mix compile`

## Syntax differences

- Modules

`defmodule <modulename> do ... end`

- Functions

`def <functioname>(<params>) do ... end`

- Base

instead of 16# elixer uses 0x for hex

- Type specs

instead of `-spec`, `@spec <functionname>(<param types>) :: <returntype>`

- Comments

`#`

- Pipe operator

Passes the result of a function as the first param of the next funciton

This erlang code is equal 
```erlang
lengthPadd(
    paddZeroes(
      addBit(MessageToPadd),
      MessageLength),
    MessageLength).
```


To this elixir code
```elixir
addBit(messageToPadd)
    |> paddZeroes(messageLength)
    |> lengthPad(messageLength)
```

## Other differences

Lists functions have different parameter(order)s