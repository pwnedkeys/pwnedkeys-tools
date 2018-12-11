module ExampleMethods
  def with_overridden_constant(mod, const, value)
    exists, original_value = if mod.const_defined?(const)
      [true, mod.const_get(const)]
    else
      [false, nil]
    end

    mod.__send__ :remove_const, const
    mod.const_set(const, value)

    yield

    mod.__send__ :remove_const, const

    if exists
      mod.const_set(const, original_value)
    end
  end
end
