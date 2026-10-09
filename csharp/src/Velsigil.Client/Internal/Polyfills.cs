// Nullable-analysis attributes missing from netstandard2.0.
#if !NET8_0_OR_GREATER
namespace System.Diagnostics.CodeAnalysis
{
    /// <summary>Specifies that when a method returns <see cref="ReturnValue"/>, the parameter is not null.</summary>
    [AttributeUsage(AttributeTargets.Parameter, Inherited = false)]
    internal sealed class NotNullWhenAttribute : Attribute
    {
        public NotNullWhenAttribute(bool returnValue) => ReturnValue = returnValue;

        public bool ReturnValue { get; }
    }

    /// <summary>Specifies that when a method returns <see cref="ReturnValue"/>, the parameter may be null.</summary>
    [AttributeUsage(AttributeTargets.Parameter, Inherited = false)]
    internal sealed class MaybeNullWhenAttribute : Attribute
    {
        public MaybeNullWhenAttribute(bool returnValue) => ReturnValue = returnValue;

        public bool ReturnValue { get; }
    }
}
#endif
