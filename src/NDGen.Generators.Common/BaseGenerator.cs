using System;
using NDGen.Core;

namespace NDGen.Generators
{
    /// <summary>
    /// Base class for all generators that implements the IGenerator interface
    /// </summary>
    public abstract class BaseGenerator : IGenerator
    {
        protected string OutputPath { get; }
        protected DefinitionLoader Loader { get; }
        protected string BaseDirectory { get; private set; } = string.Empty;

        protected BaseGenerator(string outputPath, DefinitionLoader loader)
        {
            OutputPath = outputPath ?? throw new ArgumentNullException(nameof(outputPath));
            Loader = loader ?? throw new ArgumentNullException(nameof(loader));
        }

        /// <summary>
        /// Sets the base directory for the project, to be used for resource resolution
        /// </summary>
        /// <param name="baseDirectory">The root directory of the project</param>
        public void SetBaseDirectory(string baseDirectory)
        {
            BaseDirectory = baseDirectory ?? throw new ArgumentNullException(nameof(baseDirectory));
        }

        /// <summary>
        /// Gets the path to a template file or directory based on the project structure
        /// </summary>
        /// <param name="relativePath">The path relative to the base directory</param>
        /// <returns>The full path to the template</returns>
        protected string GetTemplatePath(string relativePath)
        {
            return System.IO.Path.Combine(BaseDirectory, relativePath);
        }

        /// <summary>
        /// Executes the generation process
        /// </summary>
        public abstract void Generate();
    }
}
